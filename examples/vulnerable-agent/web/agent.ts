// Billing assistant. DELIBERATELY VULNERABLE fixture for agent-blast-radius. Do not deploy.
import { anthropic } from "@ai-sdk/anthropic";
import { Payments } from "@acme/payments";
import { generateText, stepCountIs, tool } from "ai";
import { z } from "zod";

const payments = new Payments(process.env.PAYMENTS_SECRET_KEY!);

export async function answer(question: string) {
  return generateText({
    model: anthropic("claude-sonnet-4-5"),
    prompt: question,
    stopWhen: stepCountIs(20),
    tools: {
      readPage: tool({
        description: "Read a web page",
        inputSchema: z.object({ url: z.string() }),
        execute: async ({ url }) => (await fetch(url)).text(),
      }),
      refund: tool({
        description: "Refund a charge",
        inputSchema: z.object({ charge: z.string() }),
        execute: async ({ charge }) => payments.refunds.create({ charge }),
      }),
    },
  });
}
