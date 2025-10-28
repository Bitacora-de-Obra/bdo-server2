import { Prisma } from "@prisma/client";

export interface NormalizedListItem {
  text: string;
}

export interface NormalizedPersonnelEntry {
  role: string;
  quantity?: number;
  notes?: string;
}

export interface NormalizedEquipmentEntry {
  name: string;
  status?: string;
  notes?: string;
}

export interface NormalizedWeatherRainEvent {
  start?: string;
  end?: string;
}

export interface NormalizedWeatherReport {
  summary?: string;
  temperature?: string;
  notes?: string;
  rainEvents: NormalizedWeatherRainEvent[];
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const toTrimmedString = (value: unknown): string | undefined => {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length ? trimmed : undefined;
};

const parseQuantity = (value: unknown): number | undefined => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      return undefined;
    }
    const parsed = Number(trimmed);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }
  return undefined;
};

const isNullishJson = (value: unknown) =>
  value === null ||
  value === undefined ||
  value === Prisma.DbNull ||
  value === Prisma.JsonNull;

export const normalizeListItems = (value: unknown): NormalizedListItem[] => {
  if (isNullishJson(value)) {
    return [];
  }
  const rawItems = Array.isArray(value) ? value : [value];
  const items = rawItems
    .map<NormalizedListItem | null>((item) => {
      if (!item) {
        return null;
      }
      if (typeof item === "string") {
        const text = item.trim();
        return text ? { text } : null;
      }
      if (isRecord(item)) {
        const candidates = ["text", "description", "value", "label"];
        for (const key of candidates) {
          const text = toTrimmedString(item[key]);
          if (text) {
            return { text };
          }
        }
        const role = toTrimmedString(item.role);
        if (role) {
          return { text: role };
        }
      }
      return null;
    })
    .filter((item): item is NormalizedListItem => Boolean(item));
  return items;
};

export const normalizePersonnelEntries = (
  value: unknown
): NormalizedPersonnelEntry[] => {
  if (isNullishJson(value)) {
    return [];
  }
  const rawItems = Array.isArray(value) ? value : [value];
  const items = rawItems
    .map<NormalizedPersonnelEntry | null>((item) => {
      if (!item) return null;
      if (typeof item === "string") {
        const role = item.trim();
        return role ? { role } : null;
      }
      if (isRecord(item)) {
        const role =
          toTrimmedString(item.role) ||
          toTrimmedString(item.text) ||
          toTrimmedString(item.label);
        if (!role) {
          return null;
        }
        const quantity =
          parseQuantity(item.quantity) ??
          parseQuantity(item.count) ??
          parseQuantity(item.value);
        const notes =
          toTrimmedString(item.notes) ?? toTrimmedString(item.comment);
        const entry: NormalizedPersonnelEntry = { role };
        if (quantity !== undefined) {
          entry.quantity = quantity;
        }
        if (notes) {
          entry.notes = notes;
        }
        return entry;
      }
      return null;
    })
    .filter(
      (entry): entry is NormalizedPersonnelEntry => Boolean(entry?.role?.length)
    );
  return items;
};

export const normalizeEquipmentEntries = (
  value: unknown
): NormalizedEquipmentEntry[] => {
  if (isNullishJson(value)) {
    return [];
  }
  const rawItems = Array.isArray(value) ? value : [value];
  const items = rawItems
    .map<NormalizedEquipmentEntry | null>((item) => {
      if (!item) return null;
      if (typeof item === "string") {
        const name = item.trim();
        return name ? { name } : null;
      }
      if (isRecord(item)) {
        const name =
          toTrimmedString(item.name) ||
          toTrimmedString(item.text) ||
          toTrimmedString(item.label);
        if (!name) {
          return null;
        }
        const status =
          toTrimmedString(item.status) ||
          toTrimmedString(item.condition) ||
          toTrimmedString(item.state);
        const notes =
          toTrimmedString(item.notes) ?? toTrimmedString(item.comment);
        const entry: NormalizedEquipmentEntry = { name };
        if (status) {
          entry.status = status;
        }
        if (notes) {
          entry.notes = notes;
        }
        return entry;
      }
      return null;
    })
    .filter(
      (entry): entry is NormalizedEquipmentEntry => Boolean(entry?.name?.length)
    );
  return items;
};

export const normalizeWeatherReport = (
  value: unknown
): NormalizedWeatherReport | null => {
  if (isNullishJson(value)) {
    return null;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }
    try {
      const parsed = JSON.parse(trimmed);
      return normalizeWeatherReport(parsed);
    } catch {
      return { summary: trimmed, rainEvents: [] };
    }
  }

  if (!isRecord(value)) {
    return null;
  }

  const summary =
    toTrimmedString(value.summary) ?? toTrimmedString(value.descripcion);
  const temperature =
    toTrimmedString(value.temperature) ??
    toTrimmedString(value.temperatura) ??
    toTrimmedString(value.temp);
  const notes =
    toTrimmedString(value.notes) ?? toTrimmedString(value.observaciones);

  const rawRainEvents = Array.isArray(value.rainEvents)
    ? value.rainEvents
    : [];

  const rainEvents = rawRainEvents
    .map<NormalizedWeatherRainEvent | null>((event) => {
      if (!event) {
        return null;
      }
      if (typeof event === "string") {
        const trimmed = event.trim();
        if (!trimmed) {
          return null;
        }
        if (trimmed.includes("-")) {
          const [start, end] = trimmed.split("-").map((token) => token.trim());
          if (!start && !end) {
            return null;
          }
          return {
            start: start || undefined,
            end: end || undefined,
          };
        }
        return { start: trimmed };
      }
      if (isRecord(event)) {
        const start =
          toTrimmedString(event.start) ||
          toTrimmedString(event.inicio) ||
          toTrimmedString(event.from);
        const end =
          toTrimmedString(event.end) ||
          toTrimmedString(event.fin) ||
          toTrimmedString(event.to);
        if (!start && !end) {
          return null;
        }
        return {
          start: start || undefined,
          end: end || undefined,
        };
      }
      return null;
    })
    .filter((event): event is NormalizedWeatherRainEvent => Boolean(event));

  if (!summary && !temperature && !notes && rainEvents.length === 0) {
    return null;
  }

  return {
    summary: summary || undefined,
    temperature: temperature || undefined,
    notes: notes || undefined,
    rainEvents,
  };
};
