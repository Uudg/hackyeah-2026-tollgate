// `tool-description` entries (SPEC §6.3): tool name, description and every parameter description.
import { hasInvisible } from "../normalize/index.ts";

export interface ToolTexts { toolName: string; texts: Array<{ field: string; text: string }> }

/** Pull the strings a model reads from one OpenAI tool definition. */
export function toolTexts(tool: unknown, index: number): ToolTexts {
  const fn = (tool as { function?: { name?: unknown; description?: unknown; parameters?: unknown } } | null)?.function;
  const name = typeof fn?.name === "string" ? fn.name : "";
  const texts: ToolTexts["texts"] = [];
  if (name) texts.push({ field: `tools[${index}].function.name`, text: name });
  if (typeof fn?.description === "string") texts.push({ field: `tools[${index}].function.description`, text: fn.description });
  const props = (fn?.parameters as { properties?: Record<string, { description?: unknown }> } | undefined)?.properties;
  if (props && typeof props === "object") {
    for (const [k, v] of Object.entries(props)) {
      if (typeof v?.description === "string") texts.push({ field: `tools[${index}].function.parameters.properties.${k}.description`, text: v.description });
    }
  }
  return { toolName: name, texts };
}

export interface DescriptionCheck { regex: RegExp; maxLength?: number; invisible?: boolean; htmlComments?: boolean }

/** Returns why the text matches, or null. */
export function describeMatch(text: string, c: DescriptionCheck): { reason: string; start: number; end: number } | null {
  const m = c.regex.exec(text);
  if (m) return { reason: "regex", start: m.index, end: m.index + m[0].length };
  if (c.htmlComments) {
    const h = /<!--[\s\S]*?-->/.exec(text);
    if (h) return { reason: "html_comment", start: h.index, end: h.index + h[0].length };
  }
  if (c.invisible && hasInvisible(text)) return { reason: "invisible_chars", start: 0, end: text.length };
  if (c.maxLength !== undefined && text.length > c.maxLength) return { reason: "max_length", start: 0, end: text.length };
  return null;
}
