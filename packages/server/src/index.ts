import express from 'express'
import { Request, Response } from 'express'
import path from 'path'
import cors from 'cors'
import http from 'http'
import basicAuth from 'express-basic-auth'
import { Server } from 'socket.io'
import logger from './utils/logger'
import { expressRequestLogger } from './utils/logger'
import { DataSource } from 'typeorm'
import { IChatFlow } from './Interface'
import { getNodeModulesPackagePath, getEncryptionKey } from './utils'
import { getDataSource } from './DataSource'
import { NodesPool } from './NodesPool'
import { ChatFlow } from './database/entities/ChatFlow'
import { ChatflowPool } from './ChatflowPool'
import { CachePool } from './CachePool'
import { initializeRateLimiter } from './utils/rateLimit'
import { getAPIKeys } from './utils/apiKey'
import { sanitizeMiddleware, getCorsOptions, getAllowedIframeOrigins } from './utils/XSS'
import { Telemetry } from './utils/telemetry'
import flowiseApiV1Router from './routes'
import errorHandlerMiddleware from './middlewares/errors'

declare global {
    namespace Express {
        interface Request {
            io?: Server
        }
    }
}

export class App {
    app: express.Application
    nodesPool: NodesPool
    chatflowPool: ChatflowPool
    cachePool: CachePool
    telemetry: Telemetry
    AppDataSource: DataSource = getDataSource()

    constructor() {
        this.app = express()
    }

    async initDatabase() {
        // Initialize database
        this.AppDataSource.initialize()
            .then(async () => {
                logger.info('📦 [server]: Data Source is initializing...')

                // Run Migrations Scripts
                await this.AppDataSource.runMigrations({ transaction: 'each' })

                // Initialize nodes pool
                this.nodesPool = new NodesPool()
                await this.nodesPool.initialize()

                // Initialize chatflow pool
                this.chatflowPool = new ChatflowPool()

                // Initialize API keys
                await getAPIKeys()

                // Initialize encryption key
                await getEncryptionKey()

                // Initialize Rate Limit
                const AllChatFlow: IChatFlow[] = await getAllChatFlow()
                await initializeRateLimiter(AllChatFlow)

                // Initialize cache pool
                this.cachePool = new CachePool()

                // Initialize telemetry
                this.telemetry = new Telemetry()
                logger.info('📦 [server]: Data Source has been initialized!')
            })
            .catch((err) => {
                logger.error('❌ [server]: Error during Data Source initialization:', err)
            })
    }

    async config(socketIO?: Server) {
        // Limit is needed to allow sending/receiving base64 encoded string
        const flowise_file_size_limit = process.env.FLOWISE_FILE_SIZE_LIMIT ?? '50mb'
        this.app.use(express.json({ limit: flowise_file_size_limit }))
        this.app.use(express.urlencoded({ limit: flowise_file_size_limit, extended: true }))
        if (process.env.NUMBER_OF_PROXIES && parseInt(process.env.NUMBER_OF_PROXIES) > 0)
            this.app.set('trust proxy', parseInt(process.env.NUMBER_OF_PROXIES))

        // Allow access from specified domains
        this.app.use(cors(getCorsOptions()))

        // Allow embedding from specified domains.
        this.app.use((req, res, next) => {
            const allowedOrigins = getAllowedIframeOrigins()
            if (allowedOrigins == '*') {
                next()
            } else {
                const csp = `frame-ancestors ${allowedOrigins}`
                res.setHeader('Content-Security-Policy', csp)
                next()
            }
        })

        // Switch off the default 'X-Powered-By: Express' header
        this.app.disable('x-powered-by')

        // Add the expressRequestLogger middleware to log all requests
        this.app.use(expressRequestLogger)

        // Add the sanitizeMiddleware to guard against XSS
        this.app.use(sanitizeMiddleware)

        // Make io accessible to our router on req.io
        this.app.use((req, res, next) => {
            req.io = socketIO
            next()
        })

        if (process.env.FLOWISE_USERNAME && process.env.FLOWISE_PASSWORD) {
            const username = process.env.FLOWISE_USERNAME
            const password = process.env.FLOWISE_PASSWORD
            const basicAuthMiddleware = basicAuth({
                users: { [username]: password }
            })
            const whitelistURLs = [
                '/api/v1/verify/apikey/',
                '/api/v1/chatflows/apikey/',
                '/api/v1/public-chatflows',
                '/api/v1/public-chatbotConfig',
                '/api/v1/prediction/',
                '/api/v1/vector/upsert/',
                '/api/v1/node-icon/',
                '/api/v1/components-credentials-icon/',
                '/api/v1/chatflows-streaming',
                '/api/v1/chatflows-uploads',
                '/api/v1/openai-assistants-file/download',
                '/api/v1/feedback',
                '/api/v1/get-upload-file',
                '/api/v1/ip'
            ]
            this.app.use((req, res, next) => {
                if (req.url.includes('/api/v1/')) {
                    whitelistURLs.some((url) => req.url.includes(url)) ? next() : basicAuthMiddleware(req, res, next)
                } else next()
            })
        }

        this.app.use('/api/v1', flowiseApiV1Router)

        // ----------------------------------------
        // Configure number of proxies in Host Environment
        // ----------------------------------------
        this.app.get('/api/v1/ip', (request, response) => {
            response.send({
                ip: request.ip,
                msg: 'Check returned IP address in the response. If it matches your current IP address ( which you can get by going to http://ip.nfriedly.com/ or https://api.ipify.org/ ), then the number of proxies is correct and the rate limiter should now work correctly. If not, increase the number of proxies by 1 and restart Cloud-Hosted Flowise until the IP address matches your own. Visit https://docs.flowiseai.com/configuration/rate-limit#cloud-hosted-rate-limit-setup-guide for more information.'
            })
        })

        // ----------------------------------------
        // Components
        // ----------------------------------------

        // Get all component nodes
        this.app.get('/api/v1/nodes', (req: Request, res: Response) => {
            const returnData = []
            for (const nodeName in this.nodesPool.componentNodes) {
                const clonedNode = cloneDeep(this.nodesPool.componentNodes[nodeName])
                returnData.push(clonedNode)
            }
            return res.json(returnData)
        })

        // Get all component credentials
        this.app.get('/api/v1/components-credentials', async (req: Request, res: Response) => {
            const returnData = []
            for (const credName in this.nodesPool.componentCredentials) {
                const clonedCred = cloneDeep(this.nodesPool.componentCredentials[credName])
                returnData.push(clonedCred)
            }
            return res.json(returnData)
        })

        // Get specific component node via name
        this.app.get('/api/v1/nodes/:name', (req: Request, res: Response) => {
            if (Object.prototype.hasOwnProperty.call(this.nodesPool.componentNodes, req.params.name)) {
                return res.json(this.nodesPool.componentNodes[req.params.name])
            } else {
                throw new Error(`Node ${req.params.name} not found`)
            }
        })

        // Get component credential via name
        this.app.get('/api/v1/components-credentials/:name', (req: Request, res: Response) => {
            if (!req.params.name.includes('&amp;')) {
                if (Object.prototype.hasOwnProperty.call(this.nodesPool.componentCredentials, req.params.name)) {
                    return res.json(this.nodesPool.componentCredentials[req.params.name])
                } else {
                    throw new Error(`Credential ${req.params.name} not found`)
                }
            } else {
                const returnResponse = []
                for (const name of req.params.name.split('&amp;')) {
                    if (Object.prototype.hasOwnProperty.call(this.nodesPool.componentCredentials, name)) {
                        returnResponse.push(this.nodesPool.componentCredentials[name])
                    } else {
                        throw new Error(`Credential ${name} not found`)
                    }
                }
                return res.json(returnResponse)
            }
        })

        // Returns specific component node icon via name
        this.app.get('/api/v1/node-icon/:name', (req: Request, res: Response) => {
            if (Object.prototype.hasOwnProperty.call(this.nodesPool.componentNodes, req.params.name)) {
                const nodeInstance = this.nodesPool.componentNodes[req.params.name]
                if (nodeInstance.icon === undefined) {
                    throw new Error(`Node ${req.params.name} icon not found`)
                }

                if (nodeInstance.icon.endsWith('.svg') || nodeInstance.icon.endsWith('.png') || nodeInstance.icon.endsWith('.jpg')) {
                    const filepath = nodeInstance.icon
                    res.sendFile(filepath)
                } else {
                    throw new Error(`Node ${req.params.name} icon is missing icon`)
                }
            } else {
                throw new Error(`Node ${req.params.name} not found`)
            }
        })

        // Returns specific component credential icon via name
        this.app.get('/api/v1/components-credentials-icon/:name', (req: Request, res: Response) => {
            if (Object.prototype.hasOwnProperty.call(this.nodesPool.componentCredentials, req.params.name)) {
                const credInstance = this.nodesPool.componentCredentials[req.params.name]
                if (credInstance.icon === undefined) {
                    throw new Error(`Credential ${req.params.name} icon not found`)
                }

                if (credInstance.icon.endsWith('.svg') || credInstance.icon.endsWith('.png') || credInstance.icon.endsWith('.jpg')) {
                    const filepath = credInstance.icon
                    res.sendFile(filepath)
                } else {
                    throw new Error(`Credential ${req.params.name} icon is missing icon`)
                }
            } else {
                throw new Error(`Credential ${req.params.name} not found`)
            }
        })

        // load async options
        this.app.post('/api/v1/node-load-method/:name', async (req: Request, res: Response) => {
            const nodeData: INodeData = req.body
            if (Object.prototype.hasOwnProperty.call(this.nodesPool.componentNodes, req.params.name)) {
                try {
                    const nodeInstance = this.nodesPool.componentNodes[req.params.name]
                    const methodName = nodeData.loadMethod || ''

                    const returnOptions: INodeOptionsValue[] = await nodeInstance.loadMethods![methodName]!.call(nodeInstance, nodeData, {
                        appDataSource: this.AppDataSource,
                        databaseEntities: databaseEntities
                    })

                    return res.json(returnOptions)
                } catch (error) {
                    return res.json([])
                }
            } else {
                res.status(404).send(`Node ${req.params.name} not found`)
                return
            }
        })

        // execute custom function node
        this.app.post('/api/v1/node-custom-function', async (req: Request, res: Response) => {
            const body = req.body
            const functionInputVariables = Object.fromEntries(
                [...(body?.javascriptFunction ?? '').matchAll(/\$([a-zA-Z0-9_]+)/g)].map((g) => [g[1], undefined])
            )
            const nodeData = { inputs: { functionInputVariables, ...body } }
            if (Object.prototype.hasOwnProperty.call(this.nodesPool.componentNodes, 'customFunction')) {
                try {
                    const nodeInstanceFilePath = this.nodesPool.componentNodes['customFunction'].filePath as string
                    const nodeModule = await import(nodeInstanceFilePath)
                    const newNodeInstance = new nodeModule.nodeClass()

                    const options: ICommonObject = {
                        appDataSource: this.AppDataSource,
                        databaseEntities,
                        logger
                    }

                    const returnData = await newNodeInstance.init(nodeData, '', options)
                    const result = typeof returnData === 'string' ? handleEscapeCharacters(returnData, true) : returnData

                    return res.json(result)
                } catch (error) {
                    return res.status(500).send(`Error running custom function: ${error}`)
                }
            } else {
                res.status(404).send(`Node customFunction not found`)
                return
            }
        })

        // ----------------------------------------
        // Chatflows
        // ----------------------------------------

        // Get all chatflows
        this.app.get('/api/v1/chatflows', async (req: Request, res: Response) => {
            const chatflows: IChatFlow[] = await getAllChatFlow()
            return res.json(chatflows)
        })

        // Get specific chatflow via api key
        this.app.get('/api/v1/chatflows/apikey/:apiKey', async (req: Request, res: Response) => {
            try {
                const apiKey = await getApiKey(req.params.apiKey)
                if (!apiKey) return res.status(401).send('Unauthorized')
                const chatflows = await this.AppDataSource.getRepository(ChatFlow)
                    .createQueryBuilder('cf')
                    .where('cf.apikeyid = :apikeyid', { apikeyid: apiKey.id })
                    .orWhere('cf.apikeyid IS NULL')
                    .orWhere('cf.apikeyid = ""')
                    .orderBy('cf.name', 'ASC')
                    .getMany()
                if (chatflows.length >= 1) return res.status(200).send(chatflows)
                return res.status(404).send('Chatflow not found')
            } catch (err: any) {
                return res.status(500).send(err?.message)
            }
        })

        // Get specific chatflow via id
        this.app.get('/api/v1/chatflows/:id', async (req: Request, res: Response) => {
            const chatflow = await this.AppDataSource.getRepository(ChatFlow).findOneBy({
                id: req.params.id
            })
            if (chatflow) return res.json(chatflow)
            return res.status(404).send(`Chatflow ${req.params.id} not found`)
        })

        // Get specific chatflow via id (PUBLIC endpoint, used when sharing chatbot link)
        this.app.get('/api/v1/public-chatflows/:id', async (req: Request, res: Response) => {
            const chatflow = await this.AppDataSource.getRepository(ChatFlow).findOneBy({
                id: req.params.id
            })
            if (chatflow && chatflow.isPublic) return res.json(chatflow)
            else if (chatflow && !chatflow.isPublic) return res.status(401).send(`Unauthorized`)
            return res.status(404).send(`Chatflow ${req.params.id} not found`)
        })

        // Get specific chatflow chatbotConfig via id (PUBLIC endpoint, used to retrieve config for embedded chat)
        // Safe as public endpoint as chatbotConfig doesn't contain sensitive credential
        this.app.get('/api/v1/public-chatbotConfig/:id', async (req: Request, res: Response) => {
            const chatflow = await this.AppDataSource.getRepository(ChatFlow).findOneBy({
                id: req.params.id
            })
            if (!chatflow) return res.status(404).send(`Chatflow ${req.params.id} not found`)
            const uploadsConfig = await this.getUploadsConfig(req.params.id)
            // even if chatbotConfig is not set but uploads are enabled
            // send uploadsConfig to the chatbot
            if (chatflow.chatbotConfig || uploadsConfig) {
                try {
                    const parsedConfig = chatflow.chatbotConfig ? JSON.parse(chatflow.chatbotConfig) : {}
                    return res.json({ ...parsedConfig, uploads: uploadsConfig })
                } catch (e) {
                    return res.status(500).send(`Error parsing Chatbot Config for Chatflow ${req.params.id}`)
                }
            }
            return res.status(200).send('OK')
        })

        // Get specific chatflow apiConfig via id (PUBLIC endpoint, used to retrieve config for embedded chat)
        // Safe as public endpoint as apiConfig doesn't contain sensitive credential
        this.app.get('/api/v1/public-apiConfig/:id', async (req: Request, res: Response) => {
            const chatflow = await this.AppDataSource.getRepository(ChatFlow).findOneBy({
                id: req.params.id
            })
            if (!chatflow) return res.status(404).send(`Chatflow ${req.params.id} not found`)
            if (chatflow.apiConfig) {
                try {
                    const parsedConfig = JSON.parse(chatflow.apiConfig)
                    return res.json(parsedConfig)
                } catch (e) {
                    return res.status(500).send(`Error parsing API Config for Chatflow ${req.params.id}`)
                }
            }
            return res.status(200).send('OK')
        })

        // Save chatflow
        this.app.post('/api/v1/chatflows', async (req: Request, res: Response) => {
            const body = req.body
            const newChatFlow = new ChatFlow()
            Object.assign(newChatFlow, body)

            const chatflow = this.AppDataSource.getRepository(ChatFlow).create(newChatFlow)
            const results = await this.AppDataSource.getRepository(ChatFlow).save(chatflow)

            await this.telemetry.sendTelemetry('chatflow_created', {
                version: await getAppVersion(),
                chatflowId: results.id,
                flowGraph: getTelemetryFlowObj(JSON.parse(results.flowData)?.nodes, JSON.parse(results.flowData)?.edges)
            })

            return res.json(results)
        })

        // Update chatflow
        this.app.put('/api/v1/chatflows/:id', async (req: Request, res: Response) => {
            const chatflow = await this.AppDataSource.getRepository(ChatFlow).findOneBy({
                id: req.params.id
            })

            if (!chatflow) {
                res.status(404).send(`Chatflow ${req.params.id} not found`)
                return
            }

            const body = req.body
            const updateChatFlow = new ChatFlow()
            Object.assign(updateChatFlow, body)

            updateChatFlow.id = chatflow.id
            createRateLimiter(updateChatFlow)

            this.AppDataSource.getRepository(ChatFlow).merge(chatflow, updateChatFlow)
            const result = await this.AppDataSource.getRepository(ChatFlow).save(chatflow)

            // chatFlowPool is initialized only when a flow is opened
            // if the user attempts to rename/update category without opening any flow, chatFlowPool will be undefined
            if (this.chatflowPool) {
                // Update chatflowpool inSync to false, to build flow from scratch again because data has been changed
                this.chatflowPool.updateInSync(chatflow.id, false)
            }

            return res.json(result)
        })

        // Delete chatflow via id
        this.app.delete('/api/v1/chatflows/:id', async (req: Request, res: Response) => {
            const results = await this.AppDataSource.getRepository(ChatFlow).delete({ id: req.params.id })

            try {
                // Delete all  uploads corresponding to this chatflow
                const directory = path.join(getStoragePath(), req.params.id)
                deleteFolderRecursive(directory)
            } catch (e) {
                logger.error(`[server]: Error deleting file storage for chatflow ${req.params.id}: ${e}`)
            }

            return res.json(results)
        })

        // Check if chatflow valid for streaming
        this.app.get('/api/v1/chatflows-streaming/:id', async (req: Request, res: Response) => {
            const chatflow = await this.AppDataSource.getRepository(ChatFlow).findOneBy({
                id: req.params.id
            })
            if (!chatflow) return res.status(404).send(`Chatflow ${req.params.id} not found`)

            /*** Get Ending Node with Directed Graph  ***/
            const flowData = chatflow.flowData
            const parsedFlowData: IReactFlowObject = JSON.parse(flowData)
            const nodes = parsedFlowData.nodes
            const edges = parsedFlowData.edges
            const { graph, nodeDependencies } = constructGraphs(nodes, edges)

            const endingNodeIds = getEndingNodes(nodeDependencies, graph)
            if (!endingNodeIds.length) return res.status(500).send(`Ending nodes not found`)

            const endingNodes = nodes.filter((nd) => endingNodeIds.includes(nd.id))

            let isStreaming = false
            let isEndingNodeExists = endingNodes.find((node) => node.data?.outputs?.output === 'EndingNode')

            for (const endingNode of endingNodes) {
                const endingNodeData = endingNode.data
                if (!endingNodeData) return res.status(500).send(`Ending node ${endingNode.id} data not found`)

                const isEndingNode = endingNodeData?.outputs?.output === 'EndingNode'

                if (!isEndingNode) {
                    if (
                        endingNodeData &&
                        endingNodeData.category !== 'Chains' &&
                        endingNodeData.category !== 'Agents' &&
                        endingNodeData.category !== 'Engine'
                    ) {
                        return res.status(500).send(`Ending node must be either a Chain or Agent`)
                    }
                }

                isStreaming = isEndingNode ? false : isFlowValidForStream(nodes, endingNodeData)
            }

            // Once custom function ending node exists, flow is always unavailable to stream
            const obj = { isStreaming: isEndingNodeExists ? false : isStreaming }
            return res.json(obj)
        })

        // Check if chatflow valid for uploads
        this.app.get('/api/v1/chatflows-uploads/:id', async (req: Request, res: Response) => {
            try {
                const uploadsConfig = await this.getUploadsConfig(req.params.id)
                return res.json(uploadsConfig)
            } catch (e) {
                return res.status(500).send(e)
            }
        })

        // ----------------------------------------
        // ChatMessage
        // ----------------------------------------

        // Get all chatmessages from chatflowid
        this.app.get('/api/v1/chatmessage/:id', async (req: Request, res: Response) => {
            const sortOrder = req.query?.order as string | undefined
            const chatId = req.query?.chatId as string | undefined
            const memoryType = req.query?.memoryType as string | undefined
            const sessionId = req.query?.sessionId as string | undefined
            const messageId = req.query?.messageId as string | undefined
            const startDate = req.query?.startDate as string | undefined
            const endDate = req.query?.endDate as string | undefined
            const feedback = req.query?.feedback as boolean | undefined
            let chatTypeFilter = req.query?.chatType as chatType | undefined

            if (chatTypeFilter) {
                try {
                    const chatTypeFilterArray = JSON.parse(chatTypeFilter)
                    if (chatTypeFilterArray.includes(chatType.EXTERNAL) && chatTypeFilterArray.includes(chatType.INTERNAL)) {
                        chatTypeFilter = undefined
                    } else if (chatTypeFilterArray.includes(chatType.EXTERNAL)) {
                        chatTypeFilter = chatType.EXTERNAL
                    } else if (chatTypeFilterArray.includes(chatType.INTERNAL)) {
                        chatTypeFilter = chatType.INTERNAL
                    }
                } catch (e) {
                    return res.status(500).send(e)
                }
            }

            const chatmessages = await this.getChatMessage(
                req.params.id,
                chatTypeFilter,
                sortOrder,
                chatId,
                memoryType,
                sessionId,
                startDate,
                endDate,
                messageId,
                feedback
            )
            return res.json(chatmessages)
        })

        // Get internal chatmessages from chatflowid
        this.app.get('/api/v1/internal-chatmessage/:id', async (req: Request, res: Response) => {
            const sortOrder = req.query?.order as string | undefined
            const chatId = req.query?.chatId as string | undefined
            const memoryType = req.query?.memoryType as string | undefined
            const sessionId = req.query?.sessionId as string | undefined
            const messageId = req.query?.messageId as string | undefined
            const startDate = req.query?.startDate as string | undefined
            const endDate = req.query?.endDate as string | undefined
            const feedback = req.query?.feedback as boolean | undefined

            const chatmessages = await this.getChatMessage(
                req.params.id,
                chatType.INTERNAL,
                sortOrder,
                chatId,
                memoryType,
                sessionId,
                startDate,
                endDate,
                messageId,
                feedback
            )
            return res.json(chatmessages)
        })

        // Add chatmessages for chatflowid
        this.app.post('/api/v1/chatmessage/:id', async (req: Request, res: Response) => {
            const body = req.body
            const results = await this.addChatMessage(body)
            return res.json(results)
        })

        // Delete all chatmessages from chatId
        this.app.delete('/api/v1/chatmessage/:id', async (req: Request, res: Response) => {
            const chatflowid = req.params.id
            const chatflow = await this.AppDataSource.getRepository(ChatFlow).findOneBy({
                id: chatflowid
            })
            if (!chatflow) {
                res.status(404).send(`Chatflow ${chatflowid} not found`)
                return
            }
            const chatId = req.query?.chatId as string
            const memoryType = req.query?.memoryType as string | undefined
            const sessionId = req.query?.sessionId as string | undefined
            const chatType = req.query?.chatType as string | undefined
            const isClearFromViewMessageDialog = req.query?.isClearFromViewMessageDialog as string | undefined

            const flowData = chatflow.flowData
            const parsedFlowData: IReactFlowObject = JSON.parse(flowData)
            const nodes = parsedFlowData.nodes

            try {
                await clearSessionMemory(
                    nodes,
                    this.nodesPool.componentNodes,
                    chatId,
                    this.AppDataSource,
                    sessionId,
                    memoryType,
                    isClearFromViewMessageDialog
                )
            } catch (e) {
                return res.status(500).send('Error clearing chat messages')
            }

            const deleteOptions: FindOptionsWhere<ChatMessage> = { chatflowid }
            if (chatId) deleteOptions.chatId = chatId
            if (memoryType) deleteOptions.memoryType = memoryType
            if (sessionId) deleteOptions.sessionId = sessionId
            if (chatType) deleteOptions.chatType = chatType

            // remove all related feedback records
            const feedbackDeleteOptions: FindOptionsWhere<ChatMessageFeedback> = { chatId }
            await this.AppDataSource.getRepository(ChatMessageFeedback).delete(feedbackDeleteOptions)

            // Delete all uploads corresponding to this chatflow/chatId
            if (chatId) {
                try {
                    const directory = path.join(getStoragePath(), chatflowid, chatId)
                    deleteFolderRecursive(directory)
                } catch (e) {
                    logger.error(`[server]: Error deleting file storage for chatflow ${chatflowid}, chatId ${chatId}: ${e}`)
                }
            }

            const results = await this.AppDataSource.getRepository(ChatMessage).delete(deleteOptions)
            return res.json(results)
        })

        // ----------------------------------------
        // Chat Message Feedback
        // ----------------------------------------

        // Get all chatmessage feedback from chatflowid
        this.app.get('/api/v1/feedback/:id', async (req: Request, res: Response) => {
            const chatflowid = req.params.id
            const chatId = req.query?.chatId as string | undefined
            const sortOrder = req.query?.order as string | undefined
            const startDate = req.query?.startDate as string | undefined
            const endDate = req.query?.endDate as string | undefined

            const feedback = await this.getChatMessageFeedback(chatflowid, chatId, sortOrder, startDate, endDate)

            return res.json(feedback)
        })

        // Add chatmessage feedback for chatflowid
        this.app.post('/api/v1/feedback/:id', async (req: Request, res: Response) => {
            const body = req.body
            const results = await this.addChatMessageFeedback(body)
            return res.json(results)
        })

        // Update chatmessage feedback for id
        this.app.put('/api/v1/feedback/:id', async (req: Request, res: Response) => {
            const id = req.params.id
            const body = req.body
            await this.updateChatMessageFeedback(id, body)
            return res.json({ status: 'OK' })
        })

        // ----------------------------------------
        // stats
        // ----------------------------------------
        //
        // get stats for showing in chatflow
        this.app.get('/api/v1/stats/:id', async (req: Request, res: Response) => {
            const chatflowid = req.params.id
            let chatTypeFilter = req.query?.chatType as chatType | undefined
            const startDate = req.query?.startDate as string | undefined
            const endDate = req.query?.endDate as string | undefined

            if (chatTypeFilter) {
                try {
                    const chatTypeFilterArray = JSON.parse(chatTypeFilter)
                    if (chatTypeFilterArray.includes(chatType.EXTERNAL) && chatTypeFilterArray.includes(chatType.INTERNAL)) {
                        chatTypeFilter = undefined
                    } else if (chatTypeFilterArray.includes(chatType.EXTERNAL)) {
                        chatTypeFilter = chatType.EXTERNAL
                    } else if (chatTypeFilterArray.includes(chatType.INTERNAL)) {
                        chatTypeFilter = chatType.INTERNAL
                    }
                } catch (e) {
                    return res.status(500).send(e)
                }
            }

            const chatmessages = (await this.getChatMessage(
                chatflowid,
                chatTypeFilter,
                undefined,
                undefined,
                undefined,
                undefined,
                startDate,
                endDate,
                '',
                true
            )) as Array<ChatMessage & { feedback?: ChatMessageFeedback }>
            const totalMessages = chatmessages.length

            const totalFeedback = chatmessages.filter((message) => message?.feedback).length
            const positiveFeedback = chatmessages.filter((message) => message?.feedback?.rating === 'THUMBS_UP').length

            const results = {
                totalMessages,
                totalFeedback,
                positiveFeedback
            }

            res.json(results)
        })

        // ----------------------------------------
        // Credentials
        // ----------------------------------------

        // Create new credential
        this.app.post('/api/v1/credentials', async (req: Request, res: Response) => {
            const body = req.body
            const newCredential = await transformToCredentialEntity(body)
            const credential = this.AppDataSource.getRepository(Credential).create(newCredential)
            const results = await this.AppDataSource.getRepository(Credential).save(credential)
            return res.json(results)
        })

        // Get all credentials
        this.app.get('/api/v1/credentials', async (req: Request, res: Response) => {
            if (req.query.credentialName) {
                let returnCredentials = []
                if (Array.isArray(req.query.credentialName)) {
                    for (let i = 0; i < req.query.credentialName.length; i += 1) {
                        const name = req.query.credentialName[i] as string
                        const credentials = await this.AppDataSource.getRepository(Credential).findBy({
                            credentialName: name
                        })
                        returnCredentials.push(...credentials)
                    }
                } else {
                    const credentials = await this.AppDataSource.getRepository(Credential).findBy({
                        credentialName: req.query.credentialName as string
                    })
                    returnCredentials = [...credentials]
                }
                return res.json(returnCredentials)
            } else {
                const credentials = await this.AppDataSource.getRepository(Credential).find()
                const returnCredentials = []
                for (const credential of credentials) {
                    returnCredentials.push(omit(credential, ['encryptedData']))
                }
                return res.json(returnCredentials)
            }
        })

        // Get specific credential
        this.app.get('/api/v1/credentials/:id', async (req: Request, res: Response) => {
            const credential = await this.AppDataSource.getRepository(Credential).findOneBy({
                id: req.params.id
            })

            if (!credential) return res.status(404).send(`Credential ${req.params.id} not found`)

            // Decrpyt credentialData
            const decryptedCredentialData = await decryptCredentialData(
                credential.encryptedData,
                credential.credentialName,
                this.nodesPool.componentCredentials
            )
            const returnCredential: ICredentialReturnResponse = {
                ...credential,
                plainDataObj: decryptedCredentialData
            }
            return res.json(omit(returnCredential, ['encryptedData']))
        })

        // Update credential
        this.app.put('/api/v1/credentials/:id', async (req: Request, res: Response) => {
            const credential = await this.AppDataSource.getRepository(Credential).findOneBy({
                id: req.params.id
            })

            if (!credential) return res.status(404).send(`Credential ${req.params.id} not found`)

            const body = req.body
            const updateCredential = await transformToCredentialEntity(body)
            this.AppDataSource.getRepository(Credential).merge(credential, updateCredential)
            const result = await this.AppDataSource.getRepository(Credential).save(credential)

            return res.json(result)
        })

        // Delete all credentials from chatflowid
        this.app.delete('/api/v1/credentials/:id', async (req: Request, res: Response) => {
            const results = await this.AppDataSource.getRepository(Credential).delete({ id: req.params.id })
            return res.json(results)
        })

        // ----------------------------------------
        // Tools
        // ----------------------------------------

        // Get all tools
        this.app.get('/api/v1/tools', async (req: Request, res: Response) => {
            const tools = await this.AppDataSource.getRepository(Tool).find()
            return res.json(tools)
        })

        // Get specific tool
        this.app.get('/api/v1/tools/:id', async (req: Request, res: Response) => {
            const tool = await this.AppDataSource.getRepository(Tool).findOneBy({
                id: req.params.id
            })
            return res.json(tool)
        })

        // Add tool
        this.app.post('/api/v1/tools', async (req: Request, res: Response) => {
            const body = req.body
            const newTool = new Tool()
            Object.assign(newTool, body)

            const tool = this.AppDataSource.getRepository(Tool).create(newTool)
            const results = await this.AppDataSource.getRepository(Tool).save(tool)

            await this.telemetry.sendTelemetry('tool_created', {
                version: await getAppVersion(),
                toolId: results.id,
                toolName: results.name
            })

            return res.json(results)
        })

        // Update tool
        this.app.put('/api/v1/tools/:id', async (req: Request, res: Response) => {
            const tool = await this.AppDataSource.getRepository(Tool).findOneBy({
                id: req.params.id
            })

            if (!tool) {
                res.status(404).send(`Tool ${req.params.id} not found`)
                return
            }

            const body = req.body
            const updateTool = new Tool()
            Object.assign(updateTool, body)

            this.AppDataSource.getRepository(Tool).merge(tool, updateTool)
            const result = await this.AppDataSource.getRepository(Tool).save(tool)

            return res.json(result)
        })

        // Delete tool
        this.app.delete('/api/v1/tools/:id', async (req: Request, res: Response) => {
            const results = await this.AppDataSource.getRepository(Tool).delete({ id: req.params.id })
            return res.json(results)
        })

        // ----------------------------------------
        // Assistant
        // ----------------------------------------

        // Get all assistants
        this.app.get('/api/v1/assistants', async (req: Request, res: Response) => {
            const assistants = await this.AppDataSource.getRepository(Assistant).find()
            return res.json(assistants)
        })

        // Get specific assistant
        this.app.get('/api/v1/assistants/:id', async (req: Request, res: Response) => {
            const assistant = await this.AppDataSource.getRepository(Assistant).findOneBy({
                id: req.params.id
            })
            return res.json(assistant)
        })

        // Get assistant object
        this.app.get('/api/v1/openai-assistants/:id', async (req: Request, res: Response) => {
            const credentialId = req.query.credential as string
            const credential = await this.AppDataSource.getRepository(Credential).findOneBy({
                id: credentialId
            })

            if (!credential) return res.status(404).send(`Credential ${credentialId} not found`)

            // Decrpyt credentialData
            const decryptedCredentialData = await decryptCredentialData(credential.encryptedData)
            const openAIApiKey = decryptedCredentialData['openAIApiKey']
            if (!openAIApiKey) return res.status(404).send(`OpenAI ApiKey not found`)

            const openai = new OpenAI({ apiKey: openAIApiKey })
            const retrievedAssistant = await openai.beta.assistants.retrieve(req.params.id)
            const resp = await openai.files.list()
            const existingFiles = resp.data ?? []

            if (retrievedAssistant.file_ids && retrievedAssistant.file_ids.length) {
                ;(retrievedAssistant as any).files = existingFiles.filter((file) => retrievedAssistant.file_ids.includes(file.id))
            }

            return res.json(retrievedAssistant)
        })

        // List available assistants
        this.app.get('/api/v1/openai-assistants', async (req: Request, res: Response) => {
            const credentialId = req.query.credential as string
            const credential = await this.AppDataSource.getRepository(Credential).findOneBy({
                id: credentialId
            })

            if (!credential) return res.status(404).send(`Credential ${credentialId} not found`)

            // Decrpyt credentialData
            const decryptedCredentialData = await decryptCredentialData(credential.encryptedData)
            const openAIApiKey = decryptedCredentialData['openAIApiKey']
            if (!openAIApiKey) return res.status(404).send(`OpenAI ApiKey not found`)

            const openai = new OpenAI({ apiKey: openAIApiKey })
            const retrievedAssistants = await openai.beta.assistants.list()

            return res.json(retrievedAssistants.data)
        })

        // Add assistant
        this.app.post('/api/v1/assistants', async (req: Request, res: Response) => {
            const body = req.body

            if (!body.details) return res.status(500).send(`Invalid request body`)

            const assistantDetails = JSON.parse(body.details)

            try {
                const credential = await this.AppDataSource.getRepository(Credential).findOneBy({
                    id: body.credential
                })

                if (!credential) return res.status(404).send(`Credential ${body.credential} not found`)

                // Decrpyt credentialData
                const decryptedCredentialData = await decryptCredentialData(credential.encryptedData)
                const openAIApiKey = decryptedCredentialData['openAIApiKey']
                if (!openAIApiKey) return res.status(404).send(`OpenAI ApiKey not found`)

                const openai = new OpenAI({ apiKey: openAIApiKey })

                let tools = []
                if (assistantDetails.tools) {
                    for (const tool of assistantDetails.tools ?? []) {
                        tools.push({
                            type: tool
                        })
                    }
                }

                if (assistantDetails.uploadFiles) {
                    // Base64 strings
                    let files: string[] = []
                    const fileBase64 = assistantDetails.uploadFiles
                    if (fileBase64.startsWith('[') && fileBase64.endsWith(']')) {
                        files = JSON.parse(fileBase64)
                    } else {
                        files = [fileBase64]
                    }

                    const uploadedFiles = []
                    for (const file of files) {
                        const splitDataURI = file.split(',')
                        const filename = splitDataURI.pop()?.split(':')[1] ?? ''
                        const bf = Buffer.from(splitDataURI.pop() || '', 'base64')
                        const filePath = path.join(getUserHome(), '.flowise', 'openai-assistant', filename)
                        if (!fs.existsSync(path.join(getUserHome(), '.flowise', 'openai-assistant'))) {
                            fs.mkdirSync(path.dirname(filePath), { recursive: true })
                        }
                        if (!fs.existsSync(filePath)) {
                            fs.writeFileSync(filePath, bf)
                        }

                        const createdFile = await openai.files.create({
                            file: fs.createReadStream(filePath),
                            purpose: 'assistants'
                        })
                        uploadedFiles.push(createdFile)

                        fs.unlinkSync(filePath)
                    }
                    assistantDetails.files = [...assistantDetails.files, ...uploadedFiles]
                }

                if (!assistantDetails.id) {
                    const newAssistant = await openai.beta.assistants.create({
                        name: assistantDetails.name,
                        description: assistantDetails.description,
                        instructions: assistantDetails.instructions,
                        model: assistantDetails.model,
                        tools,
                        file_ids: (assistantDetails.files ?? []).map((file: OpenAI.Files.FileObject) => file.id)
                    })
                    assistantDetails.id = newAssistant.id
                } else {
                    const retrievedAssistant = await openai.beta.assistants.retrieve(assistantDetails.id)
                    let filteredTools = uniqWith([...retrievedAssistant.tools, ...tools], isEqual)
                    filteredTools = filteredTools.filter((tool) => !(tool.type === 'function' && !(tool as any).function))

                    await openai.beta.assistants.update(assistantDetails.id, {
                        name: assistantDetails.name,
                        description: assistantDetails.description ?? '',
                        instructions: assistantDetails.instructions ?? '',
                        model: assistantDetails.model,
                        tools: filteredTools,
                        file_ids: uniqWith(
                            [
                                ...retrievedAssistant.file_ids,
                                ...(assistantDetails.files ?? []).map((file: OpenAI.Files.FileObject) => file.id)
                            ],
                            isEqual
                        )
                    })
                }

                const newAssistantDetails = {
                    ...assistantDetails
                }
                if (newAssistantDetails.uploadFiles) delete newAssistantDetails.uploadFiles

                body.details = JSON.stringify(newAssistantDetails)
            } catch (error) {
                return res.status(500).send(`Error creating new assistant: ${error}`)
            }

            const newAssistant = new Assistant()
            Object.assign(newAssistant, body)

            const assistant = this.AppDataSource.getRepository(Assistant).create(newAssistant)
            const results = await this.AppDataSource.getRepository(Assistant).save(assistant)

            await this.telemetry.sendTelemetry('assistant_created', {
                version: await getAppVersion(),
                assistantId: results.id
            })

            return res.json(results)
        })

        // Update assistant
        this.app.put('/api/v1/assistants/:id', async (req: Request, res: Response) => {
            const assistant = await this.AppDataSource.getRepository(Assistant).findOneBy({
                id: req.params.id
            })

            if (!assistant) {
                res.status(404).send(`Assistant ${req.params.id} not found`)
                return
            }

            try {
                const openAIAssistantId = JSON.parse(assistant.details)?.id

                const body = req.body
                const assistantDetails = JSON.parse(body.details)

                const credential = await this.AppDataSource.getRepository(Credential).findOneBy({
                    id: body.credential
                })

                if (!credential) return res.status(404).send(`Credential ${body.credential} not found`)

                // Decrpyt credentialData
                const decryptedCredentialData = await decryptCredentialData(credential.encryptedData)
                const openAIApiKey = decryptedCredentialData['openAIApiKey']
                if (!openAIApiKey) return res.status(404).send(`OpenAI ApiKey not found`)

                const openai = new OpenAI({ apiKey: openAIApiKey })

                let tools = []
                if (assistantDetails.tools) {
                    for (const tool of assistantDetails.tools ?? []) {
                        tools.push({
                            type: tool
                        })
                    }
                }

                if (assistantDetails.uploadFiles) {
                    // Base64 strings
                    let files: string[] = []
                    const fileBase64 = assistantDetails.uploadFiles
                    if (fileBase64.startsWith('[') && fileBase64.endsWith(']')) {
                        files = JSON.parse(fileBase64)
                    } else {
                        files = [fileBase64]
                    }

                    const uploadedFiles = []
                    for (const file of files) {
                        const splitDataURI = file.split(',')
                        const filename = splitDataURI.pop()?.split(':')[1] ?? ''
                        const bf = Buffer.from(splitDataURI.pop() || '', 'base64')
                        const filePath = path.join(getUserHome(), '.flowise', 'openai-assistant', filename)
                        if (!fs.existsSync(path.join(getUserHome(), '.flowise', 'openai-assistant'))) {
                            fs.mkdirSync(path.dirname(filePath), { recursive: true })
                        }
                        if (!fs.existsSync(filePath)) {
                            fs.writeFileSync(filePath, bf)
                        }

                        const createdFile = await openai.files.create({
                            file: fs.createReadStream(filePath),
                            purpose: 'assistants'
                        })
                        uploadedFiles.push(createdFile)

                        fs.unlinkSync(filePath)
                    }
                    assistantDetails.files = [...assistantDetails.files, ...uploadedFiles]
                }

                const retrievedAssistant = await openai.beta.assistants.retrieve(openAIAssistantId)
                let filteredTools = uniqWith([...retrievedAssistant.tools, ...tools], isEqual)
                filteredTools = filteredTools.filter((tool) => !(tool.type === 'function' && !(tool as any).function))

                await openai.beta.assistants.update(openAIAssistantId, {
                    name: assistantDetails.name,
                    description: assistantDetails.description,
                    instructions: assistantDetails.instructions,
                    model: assistantDetails.model,
                    tools: filteredTools,
                    file_ids: uniqWith(
                        [...retrievedAssistant.file_ids, ...(assistantDetails.files ?? []).map((file: OpenAI.Files.FileObject) => file.id)],
                        isEqual
                    )
                })

                const newAssistantDetails = {
                    ...assistantDetails,
                    id: openAIAssistantId
                }
                if (newAssistantDetails.uploadFiles) delete newAssistantDetails.uploadFiles

                const updateAssistant = new Assistant()
                body.details = JSON.stringify(newAssistantDetails)
                Object.assign(updateAssistant, body)

                this.AppDataSource.getRepository(Assistant).merge(assistant, updateAssistant)
                const result = await this.AppDataSource.getRepository(Assistant).save(assistant)

                return res.json(result)
            } catch (error) {
                return res.status(500).send(`Error updating assistant: ${error}`)
            }
        })

        // Delete assistant
        this.app.delete('/api/v1/assistants/:id', async (req: Request, res: Response) => {
            const assistant = await this.AppDataSource.getRepository(Assistant).findOneBy({
                id: req.params.id
            })

            if (!assistant) {
                res.status(404).send(`Assistant ${req.params.id} not found`)
                return
            }

            try {
                const assistantDetails = JSON.parse(assistant.details)

                const credential = await this.AppDataSource.getRepository(Credential).findOneBy({
                    id: assistant.credential
                })

                if (!credential) return res.status(404).send(`Credential ${assistant.credential} not found`)

                // Decrpyt credentialData
                const decryptedCredentialData = await decryptCredentialData(credential.encryptedData)
                const openAIApiKey = decryptedCredentialData['openAIApiKey']
                if (!openAIApiKey) return res.status(404).send(`OpenAI ApiKey not found`)

                const openai = new OpenAI({ apiKey: openAIApiKey })

                const results = await this.AppDataSource.getRepository(Assistant).delete({ id: req.params.id })

                if (req.query.isDeleteBoth) await openai.beta.assistants.del(assistantDetails.id)

                return res.json(results)
            } catch (error: any) {
                if (error.status === 404 && error.type === 'invalid_request_error') return res.send('OK')
                return res.status(500).send(`Error deleting assistant: ${error}`)
            }
        })

        function streamFileToUser(res: Response, filePath: string) {
            const fileStream = fs.createReadStream(filePath)
            fileStream.pipe(res)
        }

        // Download file from assistant
        this.app.post('/api/v1/openai-assistants-file', async (req: Request, res: Response) => {
            const filePath = path.join(getUserHome(), '.flowise', 'openai-assistant', req.body.fileName)
            //raise error if file path is not absolute
            if (!path.isAbsolute(filePath)) return res.status(500).send(`Invalid file path`)
            //raise error if file path contains '..'
            if (filePath.includes('..')) return res.status(500).send(`Invalid file path`)
            //only return from the .flowise openai-assistant folder
            if (!(filePath.includes('.flowise') && filePath.includes('openai-assistant'))) return res.status(500).send(`Invalid file path`)

            if (fs.existsSync(filePath)) {
                res.setHeader('Content-Disposition', contentDisposition(path.basename(filePath)))
                streamFileToUser(res, filePath)
            } else {
                return res.status(404).send(`File ${req.body.fileName} not found`)
            }
        })

        this.app.get('/api/v1/get-upload-path', async (req: Request, res: Response) => {
            return res.json({
                storagePath: getStoragePath()
            })
        })

        // stream uploaded image
        this.app.get('/api/v1/get-upload-file', async (req: Request, res: Response) => {
            try {
                if (!req.query.chatflowId || !req.query.chatId || !req.query.fileName) {
                    return res.status(500).send(`Invalid file path`)
                }
                const chatflowId = req.query.chatflowId as string
                const chatId = req.query.chatId as string
                const fileName = req.query.fileName as string

                const filePath = path.join(getStoragePath(), chatflowId, chatId, fileName)
                //raise error if file path is not absolute
                if (!path.isAbsolute(filePath)) return res.status(500).send(`Invalid file path`)
                //raise error if file path contains '..'
                if (filePath.includes('..')) return res.status(500).send(`Invalid file path`)
                //only return from the storage folder
                if (!filePath.startsWith(getStoragePath())) return res.status(500).send(`Invalid file path`)

                if (fs.existsSync(filePath)) {
                    res.setHeader('Content-Disposition', contentDisposition(path.basename(filePath)))
                    streamFileToUser(res, filePath)
                } else {
                    return res.status(404).send(`File ${fileName} not found`)
                }
            } catch (error) {
                return res.status(500).send(`Invalid file path`)
            }
        })

        // ----------------------------------------
        // Configuration
        // ----------------------------------------

        this.app.get('/api/v1/flow-config/:id', async (req: Request, res: Response) => {
            const chatflow = await this.AppDataSource.getRepository(ChatFlow).findOneBy({
                id: req.params.id
            })
            if (!chatflow) return res.status(404).send(`Chatflow ${req.params.id} not found`)
            const flowData = chatflow.flowData
            const parsedFlowData: IReactFlowObject = JSON.parse(flowData)
            const nodes = parsedFlowData.nodes
            const availableConfigs = findAvailableConfigs(nodes, this.nodesPool.componentCredentials)
            return res.json(availableConfigs)
        })

        this.app.post('/api/v1/node-config', async (req: Request, res: Response) => {
            const nodes = [{ data: req.body }] as IReactFlowNode[]
            const availableConfigs = findAvailableConfigs(nodes, this.nodesPool.componentCredentials)
            return res.json(availableConfigs)
        })

        this.app.get('/api/v1/version', async (req: Request, res: Response) => {
            const getPackageJsonPath = (): string => {
                const checkPaths = [
                    path.join(__dirname, '..', 'package.json'),
                    path.join(__dirname, '..', '..', 'package.json'),
                    path.join(__dirname, '..', '..', '..', 'package.json'),
                    path.join(__dirname, '..', '..', '..', '..', 'package.json'),
                    path.join(__dirname, '..', '..', '..', '..', '..', 'package.json')
                ]
                for (const checkPath of checkPaths) {
                    if (fs.existsSync(checkPath)) {
                        return checkPath
                    }
                }
                return ''
            }

            const packagejsonPath = getPackageJsonPath()
            if (!packagejsonPath) return res.status(404).send('Version not found')
            try {
                const content = await fs.promises.readFile(packagejsonPath, 'utf8')
                const parsedContent = JSON.parse(content)
                return res.json({ version: parsedContent.version })
            } catch (error) {
                return res.status(500).send(`Version not found: ${error}`)
            }
        })

        // ----------------------------------------
        // Scraper
        // ----------------------------------------

        this.app.get('/api/v1/fetch-links', async (req: Request, res: Response) => {
            try {
                const url = decodeURIComponent(req.query.url as string)
                const relativeLinksMethod = req.query.relativeLinksMethod as string
                if (!relativeLinksMethod) {
                    return res.status(500).send('Please choose a Relative Links Method in Additional Parameters.')
                }

                const limit = parseInt(req.query.limit as string)
                if (process.env.DEBUG === 'true') console.info(`Start ${relativeLinksMethod}`)
                const links: string[] = relativeLinksMethod === 'webCrawl' ? await webCrawl(url, limit) : await xmlScrape(url, limit)
                if (process.env.DEBUG === 'true') console.info(`Finish ${relativeLinksMethod}`)

                res.json({ status: 'OK', links })
            } catch (e: any) {
                return res.status(500).send('Could not fetch links from the URL.')
            }
        })

        // ----------------------------------------
        // Upsert
        // ----------------------------------------

        this.app.post(
            '/api/v1/vector/upsert/:id',
            upload.array('files'),
            (req: Request, res: Response, next: NextFunction) => getRateLimiter(req, res, next),
            async (req: Request, res: Response) => {
                await this.upsertVector(req, res)
            }
        )

        this.app.post('/api/v1/vector/internal-upsert/:id', async (req: Request, res: Response) => {
            await this.upsertVector(req, res, true)
        })

        // ----------------------------------------
        // Prompt from Hub
        // ----------------------------------------
        this.app.post('/api/v1/load-prompt', async (req: Request, res: Response) => {
            try {
                let hub = new Client()
                const prompt = await hub.pull(req.body.promptName)
                const templates = parsePrompt(prompt)
                return res.json({ status: 'OK', prompt: req.body.promptName, templates: templates })
            } catch (e: any) {
                return res.json({ status: 'ERROR', prompt: req.body.promptName, error: e?.message })
            }
        })

        this.app.post('/api/v1/prompts-list', async (req: Request, res: Response) => {
            try {
                const tags = req.body.tags ? `tags=${req.body.tags}` : ''
                // Default to 100, TODO: add pagination and use offset & limit
                const url = `https://api.hub.langchain.com/repos/?limit=100&${tags}has_commits=true&sort_field=num_likes&sort_direction=desc&is_archived=false`
                axios.get(url).then((response) => {
                    if (response.data.repos) {
                        return res.json({ status: 'OK', repos: response.data.repos })
                    }
                })
            } catch (e: any) {
                return res.json({ status: 'ERROR', repos: [] })
            }
        })

        // ----------------------------------------
        // Prediction
        // ----------------------------------------

        // Send input message and get prediction result (External)
        this.app.post(
            '/api/v1/prediction/:id',
            upload.array('files'),
            (req: Request, res: Response, next: NextFunction) => getRateLimiter(req, res, next),
            async (req: Request, res: Response) => {
                const chatflow = await this.AppDataSource.getRepository(ChatFlow).findOneBy({
                    id: req.params.id
                })
                if (!chatflow) return res.status(404).send(`Chatflow ${req.params.id} not found`)
                let isDomainAllowed = true
                logger.info(`[server]: Request originated from ${req.headers.origin}`)
                if (chatflow.chatbotConfig) {
                    const parsedConfig = JSON.parse(chatflow.chatbotConfig)
                    // check whether the first one is not empty. if it is empty that means the user set a value and then removed it.
                    const isValidAllowedOrigins = parsedConfig.allowedOrigins?.length && parsedConfig.allowedOrigins[0] !== ''
                    if (isValidAllowedOrigins) {
                        const originHeader = req.headers.origin as string
                        const origin = new URL(originHeader).host
                        isDomainAllowed =
                            parsedConfig.allowedOrigins.filter((domain: string) => {
                                try {
                                    const allowedOrigin = new URL(domain).host
                                    return origin === allowedOrigin
                                } catch (e) {
                                    return false
                                }
                            }).length > 0
                    }
                }

                if (isDomainAllowed) {
                    await this.buildChatflow(req, res, socketIO)
                } else {
                    return res.status(401).send(`This site is not allowed to access this chatbot`)
                }
            }
        )

        // Send input message and get prediction result (Internal)
        this.app.post('/api/v1/internal-prediction/:id', async (req: Request, res: Response) => {
            await this.buildChatflow(req, res, socketIO, true)
        })

        // ----------------------------------------
        // Marketplaces
        // ----------------------------------------

        // Get all templates for marketplaces
        this.app.get('/api/v1/marketplaces/templates', async (req: Request, res: Response) => {
            let marketplaceDir = path.join(__dirname, '..', 'marketplaces', 'chatflows')
            let jsonsInDir = fs.readdirSync(marketplaceDir).filter((file) => path.extname(file) === '.json')
            let templates: any[] = []
            jsonsInDir.forEach((file, index) => {
                const filePath = path.join(__dirname, '..', 'marketplaces', 'chatflows', file)
                const fileData = fs.readFileSync(filePath)
                const fileDataObj = JSON.parse(fileData.toString())
                const template = {
                    id: index,
                    templateName: file.split('.json')[0],
                    flowData: fileData.toString(),
                    badge: fileDataObj?.badge,
                    framework: fileDataObj?.framework,
                    categories: fileDataObj?.categories,
                    type: 'Chatflow',
                    description: fileDataObj?.description || ''
                }
                templates.push(template)
            })

            marketplaceDir = path.join(__dirname, '..', 'marketplaces', 'tools')
            jsonsInDir = fs.readdirSync(marketplaceDir).filter((file) => path.extname(file) === '.json')
            jsonsInDir.forEach((file, index) => {
                const filePath = path.join(__dirname, '..', 'marketplaces', 'tools', file)
                const fileData = fs.readFileSync(filePath)
                const fileDataObj = JSON.parse(fileData.toString())
                const template = {
                    ...fileDataObj,
                    id: index,
                    type: 'Tool',
                    framework: fileDataObj?.framework,
                    badge: fileDataObj?.badge,
                    categories: '',
                    templateName: file.split('.json')[0]
                }
                templates.push(template)
            })
            const sortedTemplates = templates.sort((a, b) => a.templateName.localeCompare(b.templateName))
            const FlowiseDocsQnAIndex = sortedTemplates.findIndex((tmp) => tmp.templateName === 'Flowise Docs QnA')
            if (FlowiseDocsQnAIndex > 0) {
                sortedTemplates.unshift(sortedTemplates.splice(FlowiseDocsQnAIndex, 1)[0])
            }
            return res.json(sortedTemplates)
        })

        // ----------------------------------------
        // Variables
        // ----------------------------------------
        this.app.get('/api/v1/variables', async (req: Request, res: Response) => {
            const variables = await getDataSource().getRepository(Variable).find()
            return res.json(variables)
        })

        // Create new variable
        this.app.post('/api/v1/variables', async (req: Request, res: Response) => {
            const body = req.body
            const newVariable = new Variable()
            Object.assign(newVariable, body)
            const variable = this.AppDataSource.getRepository(Variable).create(newVariable)
            const results = await this.AppDataSource.getRepository(Variable).save(variable)
            return res.json(results)
        })

        // Update variable
        this.app.put('/api/v1/variables/:id', async (req: Request, res: Response) => {
            const variable = await this.AppDataSource.getRepository(Variable).findOneBy({
                id: req.params.id
            })

            if (!variable) return res.status(404).send(`Variable ${req.params.id} not found`)

            const body = req.body
            const updateVariable = new Variable()
            Object.assign(updateVariable, body)
            this.AppDataSource.getRepository(Variable).merge(variable, updateVariable)
            const result = await this.AppDataSource.getRepository(Variable).save(variable)

            return res.json(result)
        })

        // Delete variable via id
        this.app.delete('/api/v1/variables/:id', async (req: Request, res: Response) => {
            const results = await this.AppDataSource.getRepository(Variable).delete({ id: req.params.id })
            return res.json(results)
        })

        // ----------------------------------------
        // API Keys
        // ----------------------------------------

        const addChatflowsCount = async (keys: any, res: Response) => {
            if (keys) {
                const updatedKeys: any[] = []
                //iterate through keys and get chatflows
                for (const key of keys) {
                    const chatflows = await this.AppDataSource.getRepository(ChatFlow)
                        .createQueryBuilder('cf')
                        .where('cf.apikeyid = :apikeyid', { apikeyid: key.id })
                        .getMany()
                    const linkedChatFlows: any[] = []
                    chatflows.map((cf) => {
                        linkedChatFlows.push({
                            flowName: cf.name,
                            category: cf.category,
                            updatedDate: cf.updatedDate
                        })
                    })
                    key.chatFlows = linkedChatFlows
                    updatedKeys.push(key)
                }
                return res.json(updatedKeys)
            }
            return res.json(keys)
        }
        // Get api keys
        this.app.get('/api/v1/apikey', async (req: Request, res: Response) => {
            const keys = await getAPIKeys()
            return addChatflowsCount(keys, res)
        })

        // Add new api key
        this.app.post('/api/v1/apikey', async (req: Request, res: Response) => {
            const keys = await addAPIKey(req.body.keyName)
            return addChatflowsCount(keys, res)
        })

        // Update api key
        this.app.put('/api/v1/apikey/:id', async (req: Request, res: Response) => {
            const keys = await updateAPIKey(req.params.id, req.body.keyName)
            return addChatflowsCount(keys, res)
        })

        // Delete new api key
        this.app.delete('/api/v1/apikey/:id', async (req: Request, res: Response) => {
            const keys = await deleteAPIKey(req.params.id)
            return addChatflowsCount(keys, res)
        })

        // Verify api key
        this.app.get('/api/v1/verify/apikey/:apiKey', async (req: Request, res: Response) => {
            try {
                const apiKey = await getApiKey(req.params.apiKey)
                if (!apiKey) return res.status(401).send('Unauthorized')
                return res.status(200).send('OK')
            } catch (err: any) {
                return res.status(500).send(err?.message)
            }
        })

        // ----------------------------------------
        // Serve UI static
        // ----------------------------------------

        const packagePath = getNodeModulesPackagePath('flowise-ui')
        const uiBuildPath = path.join(packagePath, 'build')
        const uiHtmlPath = path.join(packagePath, 'build', 'index.html')

        this.app.use('/', express.static(uiBuildPath))

        // All other requests not handled will return React app
        this.app.use((req: Request, res: Response) => {
            res.sendFile(uiHtmlPath)
        })

        // Error handling
        this.app.use(errorHandlerMiddleware)
    }

    async stopApp() {
        try {
            const removePromises: any[] = []
            removePromises.push(this.telemetry.flush())
            await Promise.all(removePromises)
        } catch (e) {
            logger.error(`❌[server]: Flowise Server shut down error: ${e}`)
        }
    }
}

let serverApp: App | undefined

export async function getAllChatFlow(): Promise<IChatFlow[]> {
    return await getDataSource().getRepository(ChatFlow).find()
}

export async function start(): Promise<void> {
    serverApp = new App()

    const port = parseInt(process.env.PORT || '', 10) || 3000
    const server = http.createServer(serverApp.app)

    const io = new Server(server, {
        cors: getCorsOptions()
    })

    await serverApp.initDatabase()
    await serverApp.config(io)

    server.listen(port, () => {
        logger.info(`⚡️ [server]: Flowise Server is listening at ${port}`)
    })
}

export function getInstance(): App | undefined {
    return serverApp
}
