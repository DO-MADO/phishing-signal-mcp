// MCP 서버 부트스트랩 (SPEC §3 / §9)
// 전송: Streamable HTTP / Remote / Stateless(no session).
//  - 세션 상태를 두지 않는다(sessionIdGenerator: undefined).
//  - 요청마다 새 McpServer+Transport를 생성해 상태 누수를 막는다(공식 stateless 패턴).
//  - 전송 계층은 의존성 최소화를 위해 Node 내장 http 사용(express 미사용).

import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { fileURLToPath } from 'node:url';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import { registerAnalyzePhishingRisk } from './tools/analyzePhishingRisk.js';
import { registerGetReportChannels } from './tools/getReportChannels.js';

export const SERVER_NAME = 'phishing-signal'; // SPEC §2 (kakao 미포함)
export const SERVER_VERSION = '0.1.0';
const MCP_PATH = '/mcp';
const MAX_BODY_BYTES = 1_000_000; // 본문 크기 가드(초장문/남용 방어)

/** 두 툴이 등록된 MCP 서버 인스턴스를 생성한다(테스트에서도 재사용). */
export function createMcpServer(): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );
  registerAnalyzePhishingRisk(server);
  registerGetReportChannels(server);
  return server;
}

function setCors(res: ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Mcp-Session-Id, Mcp-Protocol-Version');
  res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id, Mcp-Protocol-Version');
}

function sendJsonRpcError(res: ServerResponse, status: number, code: number, message: string): void {
  if (!res.headersSent) res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }));
}

/** 요청 본문을 읽어 JSON으로 파싱한다(크기 가드 포함). */
function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (raw.length === 0) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

/** 단일 MCP 요청 처리 — stateless: 인스턴스를 새로 만들고 처리 후 정리. */
async function handleMcpRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let body: unknown;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    sendJsonRpcError(res, 400, -32700, e instanceof Error ? e.message : 'Parse error');
    return;
  }

  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

  res.on('close', () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  } catch (e) {
    console.error('[phishing-signal] MCP request failed:', e);
    sendJsonRpcError(res, 500, -32603, 'Internal server error');
  }
}

/** HTTP 서버를 생성한다(listen은 호출자/startServer에서). */
export function createHttpMcpServer() {
  return createHttpServer((req, res) => {
    setCors(res);
    const url = (req.url ?? '').split('?')[0];

    if (req.method === 'OPTIONS') {
      res.writeHead(204).end();
      return;
    }

    // 헬스 체크(컨테이너/플랫폼 liveness)
    if (req.method === 'GET' && (url === '/healthz' || url === '/')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', server: SERVER_NAME, version: SERVER_VERSION }));
      return;
    }

    if (url === MCP_PATH && req.method === 'POST') {
      void handleMcpRequest(req, res);
      return;
    }

    // stateless: GET/DELETE(SSE 스트림·세션 종료) 미지원
    if (url === MCP_PATH && (req.method === 'GET' || req.method === 'DELETE')) {
      sendJsonRpcError(res, 405, -32000, 'Method not allowed (stateless server)');
      return;
    }

    sendJsonRpcError(res, 404, -32601, 'Not found');
  });
}

/** 서버를 기동한다. */
export function startServer(): void {
  const port = Number(process.env.PORT ?? 3000);
  const http = createHttpMcpServer();
  http.listen(port, () => {
    console.error(`[phishing-signal] MCP server listening on :${port}${MCP_PATH} (stateless)`);
  });
}

// 직접 실행될 때만 기동(테스트에서 import 시에는 기동하지 않음).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  startServer();
}
