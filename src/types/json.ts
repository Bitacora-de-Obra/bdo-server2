import { Prisma } from "@prisma/client";

export interface JsonObject {
  [key: string]: JsonValue;
}

export interface JsonObjectWithUndefined {
  [key: string]: JsonValue | undefined;
}

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonObject
  | JsonArray;

export type JsonValueWithUndefined = JsonValue | undefined;
export type JsonArray = JsonValue[];

export interface NormalizedWeatherReport {
  temperature?: number;
  conditions?: string;
  precipitation?: number;
  [key: string]: JsonValueWithUndefined;
}

export interface NormalizedPersonnelEntry {
  role: string;
  quantity: number;
  notes?: string;
  [key: string]: JsonValueWithUndefined;
}

export interface NormalizedEquipmentEntry {
  type: string;
  quantity: number;
  status: string;
  [key: string]: JsonValueWithUndefined;
}

export interface NormalizedListItem {
  description: string;
  status?: string;
  notes?: string;
  [key: string]: JsonValueWithUndefined;
}

export type PrismaJsonValue = Prisma.NullableJsonNullValueInput | JsonValue;
