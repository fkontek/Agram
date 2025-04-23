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
  
	  // Handle CORS preflight
	  if (request.method === "OPTIONS") {
		return new Response(null, {
		  status: 204,
		  headers: {
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "POST, GET, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type",
		  }
		});
	  }
  
	  // Registration
	  if (request.method === "POST" && url.pathname === "/register") {
		const formData = await request.formData();
		const username = formData.get("new_username");
		const rawPassword = formData.get("new_password");
		const email = formData.get("email");
  
		const encoder = new TextEncoder();
		const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(rawPassword));
		const hashedPassword = [...new Uint8Array(hashBuffer)]
		  .map(b => b.toString(16).padStart(2, "0"))
		  .join("");
  
		await env.DB.prepare(
		  "INSERT INTO Clients (username, password, email) VALUES (?, ?, ?);"
		).bind(username, hashedPassword, email).run();
  
		return new Response(
		  `<html>
			<body style="font-family: Montserrat, sans-serif; text-align: center; padding-top: 100px;">
			  <h2>Uspješna registracija!</h2>
			  <p><a href="https://pilates-reformer-agram.com" style="color: goldenrod; text-decoration: none;">← Povratak na početnu</a></p>
			</body>
		  </html>`,
		  {
			status: 200,
			headers: {
			  "Content-Type": "text/html; charset=UTF-8",
			  "Access-Control-Allow-Origin": "*"
			}
		  }
		);
	  }
  
	  // Login
	  if (request.method === "POST" && url.pathname === "/login") {
		const body = await request.text();
		const params = new URLSearchParams(body);
		const username = params.get("username");
		const password = params.get("password");
  
		const encoder = new TextEncoder();
		const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(password));
		const hashedPassword = [...new Uint8Array(hashBuffer)]
		  .map(b => b.toString(16).padStart(2, "0"))
		  .join("");
  
		const result = await env.DB.prepare(
		  "SELECT * FROM Clients WHERE username = ? AND password = ?"
		).bind(username, hashedPassword).first();
  
		if (result) {
		  return new Response("Login successful", {
			status: 200,
			headers: {
			  "Access-Control-Allow-Origin": "*",
			  "Content-Type": "text/plain"
			}
		  });
		} else {
		  return new Response("Unauthorized", {
			status: 401,
			headers: {
			  "Access-Control-Allow-Origin": "*",
			  "Content-Type": "text/plain"
			}
		  });
		}
	  }
  
	  // Fallback
	  return new Response("Not Found", {
		status: 404,
		headers: {
		  "Access-Control-Allow-Origin": "*"
		}
	  });
	}
  };
  
  
  