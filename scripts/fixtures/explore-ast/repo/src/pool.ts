export interface QueryResult {
  rows: unknown[];
}

export const pool = {
  async query(text: string): Promise<QueryResult> {
    return { rows: [{ text }] };
  },
};

export const logger = {
  debug(_message: string): void {},
  info(_message: string): void {},
};

export function audit(_name: string): void {}
