import { AgentRequest, AgentResponse } from "@/app/types/api";
import { NextResponse } from "next/server";
import { createAgent } from "./create-agent";

// CORS headers for cross-origin requests
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

/**
 * Handle OPTIONS requests for CORS preflight
 */
export async function OPTIONS() {
  return NextResponse.json({}, { headers: corsHeaders });
}

/**
 * Handles GET requests to the /api/agent endpoint.
 * This provides a simple HTML interface for testing the agent.
 * 
 * @function GET
 * @returns {NextResponse} HTML response with a simple chat interface
 */
export async function GET() {
  return new NextResponse(
    `<!DOCTYPE html>
    <html>
      <head>
        <title>Evrlink Agent API</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
          h1 { color: #333; }
          .message { margin-bottom: 10px; padding: 10px; border-radius: 5px; }
          .user { background-color: #e6f7ff; text-align: right; }
          .agent { background-color: #f0f0f0; }
          #messageInput { width: 80%; padding: 8px; margin-right: 10px; }
          button { padding: 8px 16px; background-color: #1890ff; color: white; border: none; border-radius: 4px; cursor: pointer; }
          #messages { margin: 20px 0; }
        </style>
      </head>
      <body>
        <h1>Evrlink Agent API Test Interface</h1>
        <p>This is a simple interface to test the Evrlink agent API.</p>
        
        <div id="messages"></div>
        
        <div>
          <input type="text" id="messageInput" placeholder="Type your message here..." />
          <button onclick="sendMessage()">Send</button>
        </div>
        
        <script>
          const messagesContainer = document.getElementById('messages');
          const messageInput = document.getElementById('messageInput');
          const userId = 'test_user_' + Math.random().toString(36).substring(2, 9);
          
          async function sendMessage() {
            const message = messageInput.value.trim();
            if (!message) return;
            
            // Add user message to UI
            addMessage(message, 'user');
            messageInput.value = '';
            
            try {
              // Send message to API
              const response = await fetch('/api/agent', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userMessage: message, userId })
              });
              
              const data = await response.json();
              
              if (data.error) {
                addMessage('Error: ' + data.error, 'agent');
              } else if (data.response) {
                addMessage(data.response, 'agent');
              } else {
                addMessage('No response from agent', 'agent');
              }
            } catch (error) {
              addMessage('Error: ' + error.message, 'agent');
            }
          }
          
          function addMessage(text, sender) {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message ' + sender;
            messageDiv.textContent = text;
            messagesContainer.appendChild(messageDiv);
            window.scrollTo(0, document.body.scrollHeight);
          }
          
          // Allow sending message with Enter key
          messageInput.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
              sendMessage();
            }
          });
          
          // Add initial message
          addMessage('Hello! I am the Evrlink agent. How can I help you today?', 'agent');
        </script>
      </body>
    </html>`,
    {
      headers: {
        'Content-Type': 'text/html',
        ...corsHeaders
      },
    }
  );
}
/**
 * Handles incoming POST requests to interact with the AgentKit-powered AI agent.
 * This function processes user messages and streams responses from the agent.
 *
 * @function POST
 * @param {Request & { json: () => Promise<AgentRequest> }} req - The incoming request object containing the user message.
 * @returns {Promise<NextResponse<AgentResponse>>} JSON response containing the AI-generated reply or an error message.
 *
 * @description Sends a single message to the agent and returns the agents' final response.
 *
 * @example
 * const response = await fetch("/api/agent", {
 *     method: "POST",
 *     headers: { "Content-Type": "application/json" },
 *     body: JSON.stringify({ userMessage: input }),
 * });
 */
export async function POST(
  req: Request & { json: () => Promise<AgentRequest> },
): Promise<NextResponse<AgentResponse>> {
  try {
    // 1️. Extract user message and userId from the request body
    const requestBody = await req.json();
    // Support both formats (userMessage from enhanced client, message from original client)
    const userMessage = requestBody.userMessage || requestBody.message;
    // Extract userId from request or use a default
    const userId = requestBody.userId || "default";
    
    console.log("Received request:", JSON.stringify(requestBody));
    console.log("Processing message:", userMessage);
    console.log("User ID:", userId);
    
    if (!userMessage) {
      console.error("No message found in request");
      return NextResponse.json({ error: "No message found in request" }, { status: 400, headers: corsHeaders });
    }

    try {
      // 2. Get the agent for this specific user
      console.log(`Creating agent for user ${userId}...`);
      const agent = await createAgent(userId);
      console.log(`Agent created successfully for user ${userId}`);

      // 3.Start streaming the agent's response
      console.log(`Streaming response for message: "${userMessage}"`);
      const stream = await agent.stream(
        { messages: [{ content: userMessage, role: "user" }] }, // The new message to send to the agent
        { configurable: { thread_id: "AgentKit Discussion" } }, // Customizable thread ID for tracking conversations
      );

      // 4️. Process the streamed response chunks into a single message
      let agentResponse = "";
      console.log("Processing response stream...");
      for await (const chunk of stream) {
        if ("agent" in chunk) {
          agentResponse += chunk.agent.messages[0].content;
        }
      }

      console.log("Response generated successfully");
      // 5️. Return the final response
      return NextResponse.json({ response: agentResponse }, { headers: corsHeaders });
    } catch (agentError: any) {
      console.error(`Error with agent for user ${userId}:`, agentError);
      // Provide more detailed error message
      const errorMessage = agentError.message || "Unknown agent error";
      return NextResponse.json({ 
        error: `Agent error: ${errorMessage}`,
        details: process.env.NODE_ENV === 'development' ? agentError.stack : undefined
      }, { headers: corsHeaders });
    }
  } catch (error: any) {
    console.error("Error processing request:", error);
    const errorMessage = error.message || "Unknown error";
    return NextResponse.json({ 
      error: `Failed to process message: ${errorMessage}`,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined 
    }, { headers: corsHeaders });
  }
}
