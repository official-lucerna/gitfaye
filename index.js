"use strict";

// Dependencies
const { LocalMongo } = require("./modules/localmongo")
const { execSync } = require("child_process")
const compression = require("compression")
const { parse } = require("smol-toml")
const chalk = require("chalk").default
const express = require("express")
const helmet = require("helmet")
const ky = require("ky").default
const path = require("path")
const fs = require("fs")

// Variables
const config = parse(fs.readFileSync("./config.toml", "utf8"))
const web = express()
const port = config.web.port

const dbClient = new LocalMongo("./data")
const falsePositivesCol = db.collection("false_positives")
const monitoredCol = db.collection("monitored")
const usersCol = db.collection("users")
const scansCol = db.collection("scans")
const fixedCol = db.collection("fixed")
const db = dbClient.db("gitfaye")

const MAX_CONCURRENT_SCANS = 6
const scanQueue = []
var activeScans = 0
var adminUser;

// Functions
const log = (type, message)=>{
    if(type === "i") console.log(`${chalk.cyanBright("[GITFAYE]")}${chalk.blueBright("INFORMATION")} ${message}`)
}

const initAdmin = async()=>{ // Of course we fucking add the token account itself (default).
    try {
        // Variables
        adminUser = await ky.get("https://api.github.com/user", {
            headers: { authorization: `token ${config.github.token}` }
        }).json()

        // Core
        if (!usersCol.findOne({ login: adminUser.login })) usersCol.insertOne({
            login: adminUser.login,
            avatar_url: adminUser.avatar_url,
            public_repos: adminUser.public_repos,
            name: adminUser.name,
            bio: adminUser.bio
        })
    }catch{}
}

const runScan = async(username, repoName, defaultBranch)=>{
    // Variables
    const scanId = `${username}/${repoName}`
    var existing = scansCol.findOne({ id: scanId })
    if (existing && existing.status === "running") return

    // Core
    if (!existing) {
        existing = { id: scanId, username, repo: repoName, status: "running", startedAt: Date.now(), leaks: [], vulnerabilities: [], scannedCommits: [] }

        scansCol.insertOne(existing)
    } else {
        existing.status = "running"
        existing.startedAt = Date.now()

        scansCol.updateOne({ id: scanId }, existing)
    }

    try {
        const headers = { authorization: `token ${config.github.token}` }

        if (!defaultBranch) {
            const r = await ky.get(`https://api.github.com/repos/${username}/${repoName}`, { headers }).json()
            defaultBranch = r.default_branch
        }

        const commits = await ky.get(`https://api.github.com/repos/${username}/${repoName}/commits`, {
            headers,
            searchParams: { sha: defaultBranch, per_page: 10 }
        }).json()

        var allVulns = existing.vulnerabilities || []
        var allLeaks = existing.leaks || []
        var scannedCommits = existing.scannedCommits || []

        // Avoid redundancy
        const seenVulnerabilities = new Set(allVulns.map((v) => v.id))
        const seenLeaks = new Set(allLeaks.map((l) => l.id))

        const unseenCommits = commits.filter((c) => !scannedCommits.includes(c.sha))

        for ( const commit of unseenCommits ) {
            // Variables
            const treeData = await ky.get(`https://api.github.com/repos/${username}/${repoName}/git/trees/${commit.sha}?recursive=1`, { headers }).json()
            const tree = treeData.tree || []
            const commitVulns = filesMatchesPlugin(tree)

            //! For files scan
            commitVulns.forEach((v) => {
                const id = `${v.name}-${v.matchedPaths.join(",")}`

                if (!seenVulnerabilities.has(id)) {
                    allVulns.push({ ...v, id, commit: commit.sha.substring(0, 7) })
                    seenVulnerabilities.add(id)
                }
            })

            //! For string scan
            const textFiles = tree.filter((f) => f.type === "blob" && f.size < 50000 && /\.(js|json|txt|md|yml|yaml|toml|py)$/i.test(f.path)).slice(0, 5)

            for ( const file of textFiles ) {
                try {
                    const blob = await ky.get(`https://raw.githubusercontent.com/${username}/${repoName}/${commit.sha}/${file.path}`, { headers }).text()

                    // String Matcher
                    const fileLeaks = stringMatchesPlugin(blob);
                    fileLeaks.forEach((l) => {
                        const id = `${l.name}-${file.path}-${l.risk}`

                        if (!seenLeaks.has(id)) {
                            allLeaks.push({ ...l, id, path: file.path, commit: commit.sha.substring(0, 7) })
                            seenLeaks.add(id)
                        }
                    })

                    //! Hacked NPMJS check
                    if (file.path === "package.json") {
                        try {
                            // Variables
                            const pkgJson = JSON.parse(blob)
                            const hackedDetections = await hackedNpmjsPlugin(pkgJson)

                            // Core
                            hackedDetections.forEach((d) => {
                                const id = `HACKED-${d.name}-${d.version}`

                                if (!seenVulnerabilities.has(id)) {
                                    allVulns.push({ ...d, id, path: file.path, commit: commit.sha.substring(0, 7) })

                                    seenVulnerabilities.add(id)
                                }
                            })
                        } catch{}
                    }
                } catch { }
            }

            scannedCommits.push(commit.sha)
        }

        scansCol.updateOne({ id: scanId }, {
            ...existing,
            status: "completed",
            vulnerabilities: allVulns,
            leaks: allLeaks,
            scannedCommits: scannedCommits,
            completedAt: Date.now()
        })
    } catch {
        scansCol.updateOne({ id: scanId }, { ...existing, status: "failed" })
    }
}

const processScanQueue = ()=>{
    // Variables
    if (activeScans >= MAX_CONCURRENT_SCANS || !scanQueue.length) return
    const { username, repoName, defaultBranch } = scanQueue.shift()

    // Core
    activeScans++
    runScan(username, repoName, defaultBranch).finally(() => {
        activeScans--
        processScanQueue()
    })
}

const queueScan = (username, repoName, defaultBranch)=>{
    // Variables
    if (scanQueue.some((s) => s.username === username && s.repoName === repoName)) return

    // Core
    scanQueue.push({ username, repoName, defaultBranch })
    processScanQueue()
}

// Plugin Management
if (process.argv.includes("--update-plugins")) {
    log("i", "Updating the current plugins...")
    log("i", "Deleting the current plugins...")

    if (fs.existsSync(path.join(__dirname, "plugins"))) fs.rmSync(path.join(__dirname, "plugins"), { recursive: true, force: true })
}

if (!fs.existsSync(path.join(__dirname, "plugins"))) {
    log("i", "Downloading the plugins...")
    try {
        execSync("git clone https://github.com/firstdecree/gitfaye-plugins.git plugins", {
            cwd: __dirname,
            stdio: "ignore"
        })
    }catch{}
}

// Late-Dependencies
const filesMatchesPlugin = require("./plugins/files-matches")
const hackedNpmjsPlugin = require("./plugins/hacked-npmjs")
const stringMatchesPlugin = require("./plugins/string-matches")

// Configurations
//* Express
web.set("view engine", "ejs")
web.set("views", path.join(__dirname, "views"))
web.use(helmet({ contentSecurityPolicy: false }))
web.use(compression({ level: 1 }))
web.use(express.urlencoded({ extended: true }))
web.use(express.json())
web.use(express.static(path.join(__dirname, "public")))

// Main
initAdmin()

//* API
web.post("/api/add-user", async (req, res) => {
    // Variables
    const { username } = req.body
    
    // Validations
    if (!username) return res.redirect("/")

    // Core
    try {
        const githubUser = await ky.get(`https://api.github.com/users/${username}`, {
            headers: { authorization: `token ${config.github.token}` }
        }).json()

        if (!usersCol.findOne({ login: githubUser.login })) usersCol.insertOne({
            login: githubUser.login,
            avatar_url: githubUser.avatar_url,
            public_repos: githubUser.public_repos,
            name: githubUser.name,
            bio: githubUser.bio
        })

        res.redirect("/defense")
    } catch {
        res.redirect("/defense")
    }
})

web.get("/:username/remove", async (req, res) => {
    // Variables
    const { username } = req.params

    // Validations
    if(!username) return res.redirect("/")

    // Core
    usersCol.deleteOne({ login: username })
    res.redirect("/defense")
})

web.get("/:username/scan-all", async (req, res) => {
    // Variables
    const { username } = req.params

    // Validations
    if(!username) return res.redirect("/")

    // Core
    try {
        const repos = await ky.get(`https://api.github.com/users/${username}/repos`, {
            headers: { authorization: `token ${config.github.token}` },
            searchParams: { per_page: 100 }
        }).json()

        for (const r of repos) queueScan(username, r.name, r.default_branch)
    } catch {}

    res.redirect("/defense")
})

web.get("/scan-monitored", async (req, res) => {
    // Core
    try {
        const monitored = monitoredCol.findMany()
        for (const m of monitored) queueScan(m.username, m.repoName, m.defaultBranch)
    } catch { console.error("Scan Monitored Error:", e.message) }
    res.redirect(req.get("Referrer") || "/monitored")
})

//* EJS Main
web.get("/defense", async (req, res) => {
    // Variables
    const users = usersCol.findMany()
    const scans = scansCol.findMany()
    const monitored = monitoredCol.findMany()
    const falsePositives = falsePositivesCol.findMany()

    // Core
    const fixed = fixedCol.findMany()
    res.render("defense", { users, scans, monitored, falsePositives, fixed, queueLength: scanQueue.length, activeScans })
})

web.get("/monitored", async (req, res) => {
    // Variables
    const page = Math.max(1, parseInt(req.query.page) || 1)
    const PER_PAGE = 10
    const allMonitored = monitoredCol.findMany()
    allMonitored.sort((a, b) => a.id.localeCompare(b.id))
    const total = allMonitored.length
    const scans = scansCol.findMany()
    const paginated = allMonitored.slice((page - 1) * PER_PAGE, page * PER_PAGE).map((m) => {
        const scan = scans.find((s) => s.id === m.id)
        return { ...m, lastChecked: scan ? scan.completedAt : null }
    })
    const totalPages = Math.ceil(total / PER_PAGE)

    // Core
    res.render("monitored", {
        monitoredRepos: paginated,
        page,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
    })
})

web.get("/detections", async (req, res) => {
    // Variables
    const page = Math.max(1, parseInt(req.query.page) || 1)
    const PER_PAGE = 20

    const scans = scansCol.findMany().filter((s) => s.status === "completed")
    var allDetections = []

    // Core
    for ( const scan of scans ) {
        if (scan.leaks) for ( const leak of scan.leaks ) allDetections.push({ type: "leak", repo: scan.repo, username: scan.username, date: scan.completedAt, ...leak })
        if (scan.vulnerabilities) for ( const vuln of scan.vulnerabilities ) allDetections.push({ type: "vulnerability", repo: scan.repo, username: scan.username, date: scan.completedAt, ...vuln })
    }

    allDetections.sort((a, b) => b.date - a.date) // Sort by date descending

    // Filter out false positives by repository
    const fpSet = new Set(falsePositivesCol.findMany().map((f) => f.fpKey || `${f.username}/${f.repo}/${f.detectionId}`))
    const fixSet = new Set(fixedCol.findMany().map((f) => f.fixKey || `${f.username}/${f.repo}/${f.detectionId}`))
    const showHidden = req.query.show === "hidden"
    const showFixes = req.query.show === "fixes"
    const processedDetections = allDetections.map((d) => {
        const key = `${d.username}/${d.repo}/${d.id}`
        return { ...d, isHidden: fpSet.has(key), isFixed: fixSet.has(key) }
    })

    var filteredDetections = processedDetections.filter((d) => !d.isHidden && !d.isFixed)
    if (showHidden) filteredDetections = processedDetections.filter((d) => d.isHidden)
    if (showFixes) filteredDetections = processedDetections.filter((d) => d.isFixed)

    const paginated = filteredDetections.slice((page - 1) * PER_PAGE, page * PER_PAGE)
    const hasNext = filteredDetections.length > page * PER_PAGE

    res.render("detections", {
        detections: paginated,
        page,
        hasNext,
        hasPrev: page > 1,
        showHidden,
        showFixes
    })
})

//* EJS Bottom
web.get("/:username", async (req, res) => {
    // Variables
    const { username } = req.params

    // Validations
    const dbUser = usersCol.findOne({ login: username })
    if (!dbUser) return res.redirect("/")

    // Core
    try {
        const ghUser = await ky.get(`https://api.github.com/users/${username}`, {
            headers: { authorization: `token ${config.github.token}` }
        }).json()
        var fullInfo = ghUser

        if (adminUser && username === adminUser.login) {
            fullInfo = await ky.get("https://api.github.com/user", {
                headers: { authorization: `token ${config.github.token}` }
            }).json()
        }

        res.render("dashboard", {
            user: fullInfo,
            isAdmin: adminUser && username === adminUser.login
        })
    } catch {
        res.redirect("/")
    }
})

//! END 1
web.get("/:username/repositories", async (req, res) => {
    // Variables
    const { username } = req.params
    const page = Math.max(1, parseInt(req.query.page) || 1)
    const sort = ["updated", "created", "pushed", "full_name"].includes(req.query.sort) ? req.query.sort : "updated"
    const type = ["all", "owner", "public", "private", "member"].includes(req.query.type) ? req.query.type : "all"
    const language = req.query.language || ""
    const q = req.query.q || ""
    const PER_PAGE = 10

    // Validations
    if(!username) return res.redirect("/")

    // Core
    try {
        // Variables
        const ghUser = await ky.get(`https://api.github.com/users/${username}`, {
            headers: { authorization: `token ${config.github.token}` }
        }).json()

        const repos = await ky.get(`https://api.github.com/users/${username}/repos`, {
            headers: { authorization: `token ${config.github.token}` },
            searchParams: { per_page: 100, sort, type: type === "all" ? "owner" : type } // GitHub API "type" for /users/:u/repos is limited
        }).json()

        // Core
        const allFiltered = repos.filter((r) => {
            const matchLang = language ? (r.language || "").toLowerCase() === language.toLowerCase() : true
            const matchQ = q ? (r.name + (r.description || "")).toLowerCase().includes(q.toLowerCase()) : true
            return matchLang && matchQ
        })

        const totalFiltered = allFiltered.length
        const pageRepos = allFiltered.slice((page - 1) * PER_PAGE, page * PER_PAGE)
        const hasNext = totalFiltered > page * PER_PAGE
        const languages = [...new Set(repos.map((r) => r.language).filter(Boolean))].sort()
        const monitoredList = monitoredCol.findMany().filter((m) => m.username.toLowerCase() === username.toLowerCase()).map((m) => m.repoName.toLowerCase())

        res.render("repositories", {
            user: ghUser,
            repos: pageRepos,
            page,
            hasNext,
            hasPrev: page > 1,
            sort,
            type,
            language,
            q,
            languages,
            orgs: [],
            monitoredList
        })
    } catch {
        res.redirect(`/${username}`)
    }
})

web.get("/:username/monitor-all", async (req, res) => {
    // Variables
    const { username } = req.params

    // Validations
    if(!username) return res.redirect("/")

    // Core
    try {
        const repos = await ky.get(`https://api.github.com/users/${username}/repos`, {
            headers: { authorization: `token ${config.github.token}` },
            searchParams: { per_page: 100 }
        }).json();

        for ( const r of repos ) {
            const scanId = `${username}/${r.name}`

            if (!monitoredCol.findOne({ id: scanId })) monitoredCol.insertOne({ id: scanId, username, repoName: r.name, defaultBranch: r.default_branch })
        }
    } catch {}

    res.redirect(req.get("Referrer") || `/${username}/repositories`)
})

web.get("/:username/repository/:name/scan", async (req, res) => {
    // Variables
    const { username, name } = req.params

    // Core
    queueScan(username, name)
    res.redirect(req.get("Referrer") || `/${username}/repositories`);
})

web.get("/:username/repository/:name/monitor", async (req, res) => {
    // Variables
    const { username, name } = req.params
    const scanId = `${username}/${name}`

    // COre
    if (!monitoredCol.findOne({ id: scanId })) monitoredCol.insertOne({ id: scanId, username, repoName: name })
    res.redirect(req.get("Referrer") || `/${username}/repositories`)
})

web.get("/:username/repository/:name/unmonitor", async (req, res) => {
    // Variables
    const { username, name } = req.params
    const scanId = `${username}/${name}`

    // Core
    monitoredCol.deleteOne({ id: scanId })
    res.redirect(req.get("Referrer") || `/${username}/repositories`)
})

//! END 2
web.get("/:username/repository/:repo/detection/:id/ignore", async (req, res) => {
    // Variables
    const { username, repo, id } = req.params
    const fpKey = `${username}/${repo}/${id}`

    // Core
    if (!falsePositivesCol.findOne({ fpKey })) falsePositivesCol.insertOne({ fpKey, detectionId: id, username, repo, addedAt: Date.now() })
    res.redirect(req.get("Referrer") || "/detections")
})

web.get("/:username/repository/:repo/detection/:id/remove-ignore", async (req, res) => {
    // Variables
    const { username, repo, id } = req.params

    // Core
    falsePositivesCol.deleteOne({ detectionId: id, username, repo })
    res.redirect(req.get("Referrer") || "/detections")
})

web.get("/:username/repository/:repo/detection/:id/fixed", async (req, res) => {
    // Variables
    const { username, repo, id } = req.params
    const fixKey = `${username}/${repo}/${id}`

    // Core
    if (!fixedCol.findOne({ fixKey })) fixedCol.insertOne({ fixKey, detectionId: id, username, repo, addedAt: Date.now() })
    res.redirect(req.get("Referrer") || "/detections")
})

web.get("/:username/repository/:repo/detection/:id/remove-fixed", async (req, res) => {
    // Variables
    const { username, repo, id } = req.params

    // Core
    fixedCol.deleteOne({ detectionId: id, username, repo })
    res.redirect(req.get("Referrer") || "/detections")
})

web.get("/:username/repository/:name", async (req, res) => {
    // Variables
    const { username, name } = req.params
    const filePath = req.query.path || ""
    const branch = req.query.branch || ""

    // Core
    try {
        // Variables
        const headers = { authorization: `token ${config.github.token}` }
        const repoPath = `${username}/${name}`
        const [ repoInfo, branches, langs, contributorsList ] = await Promise.all([
            ky.get(`https://api.github.com/repos/${repoPath}`, { headers }).json(),
            ky.get(`https://api.github.com/repos/${repoPath}/branches`, { headers }).json(),
            ky.get(`https://api.github.com/repos/${repoPath}/languages`, { headers }).json(),
            ky.get(`https://api.github.com/repos/${repoPath}/contributors`, { headers }).json()
        ])
        const ref = branch || repoInfo.default_branch
        const [ rawContents, commits ] = await Promise.all([
            ky.get(`https://api.github.com/repos/${repoPath}/contents/${filePath}`, { headers, searchParams: { ref } }).json(),
            ky.get(`https://api.github.com/repos/${repoPath}/commits`, { headers, searchParams: { sha: ref, per_page: 1, ...(filePath ? { path: filePath } : {}) } }).json()
        ])
        const contents = Array.isArray(rawContents) ? rawContents : []

        // Core
        var readmeContent;
        try {
            const rd = await ky.get(`https://api.github.com/repos/${repoPath}/readme`, { headers, searchParams: { ref } }).json()
            readmeContent = Buffer.from(rd.content, "base64").toString("utf8")
        } catch { }

        res.render("repository", {
            user: { login: username }, // Use fake user obj for simple header compat
            repo: repoInfo,
            contents,
            lastCommit: commits[0],
            branches,
            currentBranch: ref,
            currentPath: filePath,
            readme: readmeContent,
            languages: langs,
            contributors: contributorsList,
            commitCount: 0 // Skipping calculation for speed
        })
    } catch { res.redirect(`/${username}/repositories`) }
})

//* Handlers
setInterval(() => {
    log("i", "Running scheduled monitor checks (every 30 minutes)...")

    //* The monitored repositories
    const monitored = monitoredCol.findMany();
    for ( const m of monitored ) queueScan(m.username, m.repoName, m.defaultBranch)
}, 30 * 60 * 1000) // 30 Minutes
web.use("/{*any}", (req, res)=>res.redirect("/"))
web.listen(port, () => log("i", `GitFaye running on http://localhost:${port}`))