import { toast } from "@/hooks/use-toast";

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
): Promise<Response> {
  try {
    const res = await fetch(url, {
      method,
      headers: data ? { "Content-Type": "application/json" } : {},
      body: data ? JSON.stringify(data) : undefined,
      credentials: "include",
    });

    if (!res.ok) {
      const text = (await res.text()) || res.statusText;
      throw new Error(`${res.status}: ${text}`);
    }

    return res;
  } catch (error) {
    if (error instanceof Error) {
      toast({
        title: "API Error",
        description: error.message,
        variant: "destructive",
      });
    }
    throw error;
  }
}
