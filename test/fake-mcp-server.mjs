// A minimal stdio MCP server: answers initialize, tools/list and tools/call
// (echo, and a tool that always fails). Enough to drive the proxy end to end.
import { createInterface } from 'node:readline';

const reply = (id, result) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');

createInterface({ input: process.stdin }).on('line', (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  switch (msg.method) {
    case 'initialize':
      return reply(msg.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'fake', version: '0' } });
    case 'tools/list':
      return reply(msg.id, {
        tools: [
          { name: 'echo', description: 'echo', inputSchema: { type: 'object', properties: { text: { type: 'string' } } } },
          { name: 'explode', description: 'always fails', inputSchema: { type: 'object' } },
        ],
      });
    case 'tools/call':
      if (msg.params.name === 'explode') return reply(msg.id, { content: [{ type: 'text', text: 'boom' }], isError: true });
      return reply(msg.id, { content: [{ type: 'text', text: msg.params.arguments.text }] });
    default:
      if (msg.id !== undefined) reply(msg.id, {});
  }
});
process.stdin.on('end', () => process.exit(0));
