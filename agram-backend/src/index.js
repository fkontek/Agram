/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export default {
	async fetch(request, env) {
		const url = new URL(request.url);

	  if (request.method === "POST" && url.pathname === "/register") {
		const formData = await request.formData();
		const username = formData.get("new_username");
		const rawPassword = formData.get("new_password");
		const email = formData.get("email");
  
		// Hash password using SHA-256
		const encoder = new TextEncoder();
		const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(rawPassword));
		const hashedPassword = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");
  
		// Insert into database
		await env.DB.prepare(
		  "INSERT INTO Clients (username, password, email) VALUES (?, ?, ?);"
		).bind(username, hashedPassword, email).run();
  
		return new Response("Uspješna registracija!", { status: 200 });
	  }
  
	  return new Response("Not Found", { status: 404 });
	},
  };