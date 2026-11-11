export interface QueryResult {
  rows: unknown[];
}

export const pool = {
  async query(text: string): Promise<QueryResult> {
    return { rows: [{ text }] };
  },
};
