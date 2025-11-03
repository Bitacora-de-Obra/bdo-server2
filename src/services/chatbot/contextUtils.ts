import OpenAI from "openai";

export type ChatbotContextSection = {
  id: string;
  heading: string;
  body: string;
  priority?: number;
};

export const sectionToText = (section: ChatbotContextSection) =>
  `${section.heading}:\n${section.body}`;

export const cosineSimilarity = (a: number[], b: number[]) => {
  if (a.length !== b.length || !a.length) {
    return 0;
  }
  let dot = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i += 1) {
    const valA = a[i];
    const valB = b[i];
    dot += valA * valB;
    normA += valA * valA;
    normB += valB * valB;
  }

  if (!normA || !normB) {
    return 0;
  }

  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
};

type SelectSectionsParams = {
  query: string;
  sections: ChatbotContextSection[];
  openaiClient: OpenAI;
  maxSections?: number;
  embeddingModel?: string;
};

export const selectRelevantSections = async ({
  query,
  sections,
  openaiClient,
  maxSections = 6,
  embeddingModel = process.env.OPENAI_EMBEDDING_MODEL || "text-embedding-3-small",
}: SelectSectionsParams) => {
  if (!sections.length) {
    return sections;
  }

  const pinned = sections.filter((section) => (section.priority ?? 0) > 0);
  const remaining = sections.filter((section) => (section.priority ?? 0) <= 0);

  const slotsForRanking = Math.max(maxSections - pinned.length, 0);
  if (!slotsForRanking) {
    return pinned.slice(0, maxSections);
  }

  const inputs = [query, ...remaining.map(sectionToText)];

  try {
    const embeddingsResponse = await openaiClient.embeddings.create({
      model: embeddingModel,
      input: inputs,
    });

    const [queryEmbedding, ...sectionEmbeddings] = embeddingsResponse.data.map(
      (row) => row.embedding
    );

    const scored = remaining.map((section, index) => ({
      section,
      score: cosineSimilarity(queryEmbedding, sectionEmbeddings[index]),
    }));

    scored.sort((a, b) => b.score - a.score);

    const ranked = scored.slice(0, slotsForRanking).map((item) => item.section);

    const uniqueById = new Map<string, ChatbotContextSection>();
    [...pinned, ...ranked].forEach((section) => {
      if (!uniqueById.has(section.id)) {
        uniqueById.set(section.id, section);
      }
    });

    return Array.from(uniqueById.values()).slice(0, maxSections);
  } catch (error) {
    console.warn("No fue posible calcular embeddings del chatbot:", error);
    const fallback = remaining.slice(0, slotsForRanking);
    const uniqueById = new Map<string, ChatbotContextSection>();
    [...pinned, ...fallback].forEach((section) => {
      if (!uniqueById.has(section.id)) {
        uniqueById.set(section.id, section);
      }
    });
    return Array.from(uniqueById.values()).slice(0, maxSections);
  }
};
