// OpenAI chat-completions wire shapes. Parsed with zod at the boundary; unknown fields pass through.
import { z } from "zod";

export const ToolCallSchema = z.object({
  id: z.string().default(""),
  type: z.literal("function").default("function"),
  function: z.object({ name: z.string(), arguments: z.string() }),
}).passthrough();
export type ToolCall = z.infer<typeof ToolCallSchema>;

const ContentPart = z.object({ type: z.string(), text: z.string().optional() }).passthrough();

export const ChatMessageSchema = z.object({
  role: z.enum(["system", "developer", "user", "assistant", "tool"]),
  content: z.union([z.string(), z.array(ContentPart), z.null()]).optional(),
  tool_calls: z.array(ToolCallSchema).optional(),
  tool_call_id: z.string().optional(),
  name: z.string().optional(),
}).passthrough();
export type ChatMessage = z.infer<typeof ChatMessageSchema>;

export const ChatRequestSchema = z.object({
  model: z.string().min(1),
  messages: z.array(ChatMessageSchema).min(1),
  tools: z.array(z.unknown()).optional(),
  stream: z.boolean().optional(),
  max_tokens: z.number().int().positive().optional(),
}).passthrough();
export type ChatRequest = z.infer<typeof ChatRequestSchema>;

export const ChatCompletionSchema = z.object({
  id: z.string(),
  object: z.string().default("chat.completion"),
  created: z.number().default(() => Math.floor(Date.now() / 1000)),
  model: z.string(),
  choices: z.array(z.object({
    index: z.number().default(0),
    message: z.object({
      role: z.string().default("assistant"),
      content: z.string().nullable().default(null),
      tool_calls: z.array(ToolCallSchema).optional(),
    }).passthrough(),
    finish_reason: z.string().nullable().default("stop"),
  }).passthrough()),
  usage: z.object({ prompt_tokens: z.number(), completion_tokens: z.number(), total_tokens: z.number().optional() }).optional(),
}).passthrough();
export type ChatCompletion = z.infer<typeof ChatCompletionSchema>;

/** Text of a message for scanning: string content, or the text parts joined. */
export function messageText(m: ChatMessage): string {
  if (typeof m.content === "string") return m.content;
  if (Array.isArray(m.content)) return m.content.map((p) => p.text ?? "").filter(Boolean).join("\n");
  return "";
}

export const estimateTokens = (chars: number) => Math.ceil(chars / 4);
