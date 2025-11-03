import { selectRelevantSections, cosineSimilarity } from "../services/chatbot/contextUtils";
import type { ChatbotContextSection } from "../services/chatbot/contextUtils";

describe("cosineSimilarity", () => {
  it("returns 1 for identical vectors", () => {
    expect(cosineSimilarity([1, 2, 3], [1, 2, 3])).toBeCloseTo(1);
  });

  it("returns 0 for orthogonal vectors", () => {
    expect(cosineSimilarity([1, 0], [0, 1])).toBeCloseTo(0);
  });

  it("handles differing lengths gracefully", () => {
    expect(cosineSimilarity([1, 0], [1])).toBe(0);
  });
});

describe("selectRelevantSections", () => {
  const sections: ChatbotContextSection[] = [
    {
      id: "pinned",
      heading: "Resumen ejecutivo del proyecto",
      body: "Proyecto de infraestructura vial con prórrogas recientes.",
      priority: 2,
    },
    {
      id: "progress",
      heading: "Avance físico",
      body: "El avance ejecutado es del 78% con énfasis en pavimentación.",
    },
    {
      id: "safety",
      heading: "Seguridad",
      body: "Se registran inspecciones de seguridad y reportes HSE.",
    },
  ];

  const buildMockOpenAI = () => ({
    embeddings: {
      create: jest.fn(),
    },
  });

  it("prioritizes pinned sections and ranks remaining by similarity", async () => {
    const mockOpenAI = buildMockOpenAI();
    mockOpenAI.embeddings.create.mockResolvedValue({
      data: [
        { embedding: [1, 0] }, // query
        { embedding: [0.9, 0.1] }, // progress
        { embedding: [0.1, 0.9] }, // safety
      ],
    });

    const result = await selectRelevantSections({
      query: "¿Cómo va el avance físico?",
      sections,
      openaiClient: mockOpenAI as any,
    });

    expect(mockOpenAI.embeddings.create).toHaveBeenCalled();
    expect(result.map((section) => section.id)).toEqual([
      "pinned",
      "progress",
      "safety",
    ]);
  });

  it("falls back to deterministic ordering when embeddings fail", async () => {
    const mockOpenAI = buildMockOpenAI();
    mockOpenAI.embeddings.create.mockRejectedValue(new Error("boom"));

    const result = await selectRelevantSections({
      query: "Cuéntame sobre seguridad industrial",
      sections,
      openaiClient: mockOpenAI as any,
      maxSections: 2,
    });

    expect(result.map((section) => section.id)).toEqual(["pinned", "progress"]);
  });
});
