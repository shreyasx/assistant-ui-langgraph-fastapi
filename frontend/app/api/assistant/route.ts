import { NextRequest } from "next/server";
export const runtime = "nodejs"; // keep stream intact

export async function POST(req: NextRequest) {
	console.log("[ROUTE] Received POST /api/assistant");
	const body = await req.text();
	console.log("[ROUTE] Request body:", body);
	const resp = await fetch(`${process.env.BACKEND_URL}/api/chat`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body,
	});
	console.log(
		"[ROUTE] Streaming response from backend with status:",
		resp.status
	);
	return new Response(resp.body, {
		status: resp.status,
		headers: {
			"Content-Type": "text/event-stream",
			"Cache-Control": "no-cache",
			Connection: "keep-alive",
		},
	});
}
