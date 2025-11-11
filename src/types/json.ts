import { Prisma } from "@prisma/client";

export interface JsonObject {
  [key: string]: JsonValue;
}

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonObject
  | JsonArray;
export type JsonArray = JsonValue[];

export interface NormalizedWeatherReport {
  temperature?: number;
  conditions?: string;
  precipitation?: number;
  [key: string]: JsonValue | undefined;
}

export interface NormalizedPersonnelEntry {
  role: string;
  quantity: number;
  notes?: string;
  [key: string]: JsonValue | undefined;
}

export interface NormalizedEquipmentEntry extends JsonObject {
  type: string;
  quantity: number;
  status: string;
}

export interface NormalizedListItem extends JsonObject {
  description: string;
  status?: string;
  notes?: string;
}

export type PrismaJsonValue = Prisma.NullableJsonNullValueInput | JsonValue;
