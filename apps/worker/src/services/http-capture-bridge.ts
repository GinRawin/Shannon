// A CLI request is executed by the same live collector as a structured tool request.
import { chmod, mkdtemp } from 'node:fs/promises';
import { createServer, request } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { ToolDefinition } from '@earendil-works/pi-coding-agent';

interface Route {
  tool: ToolDefinition;
  controller: AbortController;
  cwd: string;
}
const routes = new Map<string, Route>();
let bridge: Promise<string> | undefined;

async function startBridge(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'shannon-capture-'));
  const socket = path.join(directory, 'host.sock');
  const server = createServer(async (req, res) => {
    try {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (Buffer.byteLength(body) > 1024 * 1024) throw new Error('Capture arguments exceed 1 MiB');
      }
      const input = JSON.parse(body) as {
        directory: string;
        finding_id: string;
        curl_arguments: string[];
        cwd?: string;
      };
      const route = routes.get(`${path.resolve(input.directory)}:${input.finding_id}`);
      if (!route) throw new Error('No active collector for this run and finding.');
      const controller = new AbortController();
      const signal = AbortSignal.any([route.controller.signal, controller.signal]);
      res.on('close', () => {
        if (!res.writableEnded) controller.abort();
      });
      const result = await route.tool.execute(
        'shannon-curl',
        {
          vulnerability_id: input.finding_id,
          curl_arguments: input.curl_arguments,
          // Preserve the CLI shell cwd; structured requests default to the assessed workspace.
          cwd: input.cwd ?? route.cwd,
        },
        signal,
        undefined,
        undefined as never,
      ); // This collector tool does not use an agent context.
      res.setHeader('Content-Type', 'application/json');
      res.end(
        result.content
          .filter((part) => part.type === 'text')
          .map((part) => part.text)
          .join('\n'),
      );
    } catch (error) {
      res.statusCode = 400;
      res.end(JSON.stringify({ status: 'error', message: (error as Error).message }));
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socket, resolve);
  });
  await chmod(socket, 0o600);
  server.unref();
  process.env.SHANNON_CAPTURE_SOCKET = socket;
  return socket;
}

export async function registerCaptureBridge(args: {
  directory: string;
  findingIds: ReadonlySet<string>;
  tool: ToolDefinition;
  cwd: string;
}): Promise<() => void> {
  bridge ??= startBridge().catch((error) => {
    bridge = undefined;
    throw error;
  });
  await bridge;
  const route: Route = { tool: args.tool, controller: new AbortController(), cwd: args.cwd };
  const keys = [...args.findingIds].map((id) => `${path.resolve(args.directory)}:${id}`);
  for (const key of keys)
    if (routes.has(key)) throw new Error('An HTTP collector for this run and finding is already active.');
  for (const key of keys) routes.set(key, route);
  return () => {
    route.controller.abort();
    for (const key of keys) if (routes.get(key) === route) routes.delete(key);
  };
}

export function captureViaBridge(
  socket: string,
  input: {
    directory: string;
    finding_id: string;
    curl_arguments: string[];
    cwd: string;
  },
): Promise<{
  status: string;
  message?: string;
  stdout?: string;
  stderr?: string;
  exit_code?: number;
  capture_id?: string;
  file?: string;
}> {
  return new Promise((resolve, reject) => {
    const req = request(
      { socketPath: socket, path: '/', method: 'POST', headers: { 'Content-Type': 'application/json' } },
      async (res) => {
        try {
          let body = '';
          for await (const chunk of res) body += chunk;
          resolve(JSON.parse(body));
        } catch (error) {
          reject(error);
        }
      },
    );
    req.once('error', reject);
    req.end(JSON.stringify(input));
  });
}
