import {
  PrismaClient,
  CommitmentStatus,
  EntryStatus,
  CommunicationStatus,
  CommunicationDirection,
  SignatureTaskStatus,
} from "@prisma/client";

const MS_PER_DAY = 24 * 60 * 60 * 1000;

type NotificationUrgency = "overdue" | "due_soon" | "info";

export type UserNotification = {
  id: string;
  type: "commitment_due" | "log_entry_assigned" | "communication_assigned";
  urgency: NotificationUrgency;
  message: string;
  sourceDescription: string;
  relatedView: "minutes" | "logbook" | "communications";
  relatedItemType: "acta" | "logEntry" | "communication";
  relatedItemId: string;
  createdAt: string;
  isRead: boolean;
};

const startOfDay = (date: Date) => {
  const normalized = new Date(date);
  normalized.setHours(0, 0, 0, 0);
  return normalized;
};

const determineUrgency = (dueDate?: Date | null) => {
  if (!dueDate || Number.isNaN(dueDate.getTime())) {
    return { urgency: "info" as NotificationUrgency, daysUntilDue: null };
  }

  const today = startOfDay(new Date());
  const due = startOfDay(dueDate);
  const diffDays = Math.ceil((due.getTime() - today.getTime()) / MS_PER_DAY);

  if (diffDays < 0) {
    return { urgency: "overdue" as NotificationUrgency, daysUntilDue: diffDays };
  }
  if (diffDays <= 3) {
    return { urgency: "due_soon" as NotificationUrgency, daysUntilDue: diffDays };
  }

  return { urgency: "info" as NotificationUrgency, daysUntilDue: diffDays };
};

export const buildUserNotifications = async (
  prisma: PrismaClient,
  userId: string
): Promise<UserNotification[]> => {
  const notifications: UserNotification[] = [];

  const commitments = await prisma.commitment.findMany({
    where: {
      responsibleId: userId,
      status: { in: [CommitmentStatus.PENDING, CommitmentStatus.DELAYED] },
    },
    include: {
      acta: {
        select: {
          id: true,
          number: true,
          title: true,
        },
      },
    },
  });

  commitments.forEach((commitment) => {
    const { urgency, daysUntilDue } = determineUrgency(commitment.dueDate);
    const actaLabelParts = [
      commitment.acta?.number ? `Acta ${commitment.acta.number}` : null,
      commitment.acta?.title || null,
    ].filter(Boolean);

    let messagePrefix = "Compromiso asignado";
    if (urgency === "overdue" || commitment.status === CommitmentStatus.DELAYED) {
      messagePrefix = "Compromiso vencido";
    } else if (urgency === "due_soon" && typeof daysUntilDue === "number") {
      const suffix =
        daysUntilDue === 0
          ? "vence hoy"
          : `vence en ${daysUntilDue} día${daysUntilDue === 1 ? "" : "s"}`;
      messagePrefix = `Compromiso ${suffix}`;
    }

    notifications.push({
      id: `commitment-${commitment.id}`,
      type: "commitment_due",
      urgency:
        urgency === "overdue" && commitment.status === CommitmentStatus.DELAYED
          ? "overdue"
          : urgency,
      message: `${messagePrefix}: ${commitment.description}`,
      sourceDescription: actaLabelParts.join(" · ") || "Compromiso asignado",
      relatedView: "minutes",
      relatedItemType: "acta",
      relatedItemId: commitment.actaId,
      createdAt: (commitment.updatedAt || commitment.createdAt).toISOString(),
      isRead: false,
    });
  });

  const logEntries = await prisma.logEntry.findMany({
    where: {
      OR: [
        {
          assignees: {
            some: { id: userId },
          },
        },
        {
          signatureTasks: {
            some: {
              signerId: userId,
              status: SignatureTaskStatus.PENDING,
            },
          },
        },
      ],
    },
    include: {
      assignees: { select: { id: true } },
      signatureTasks: {
        where: {
          signerId: userId,
          status: SignatureTaskStatus.PENDING,
        },
        select: {
          id: true,
          assignedAt: true,
          createdAt: true,
        },
      },
    },
  });

  logEntries.forEach((entry) => {
    const isAssignedReviewer =
      entry.assignees?.some((assignee) => assignee.id === userId) &&
      (entry.status === EntryStatus.NEEDS_REVIEW ||
        entry.status === EntryStatus.SUBMITTED);

    const { urgency } = determineUrgency(entry.activityEndDate);

    if (isAssignedReviewer) {
      notifications.push({
        id: `log-entry-${entry.id}`,
        type: "log_entry_assigned",
        urgency,
        message:
          urgency === "overdue"
            ? `Revisión vencida: ${entry.title}`
            : `Revisión pendiente: ${entry.title}`,
        sourceDescription: `Anotación #${entry.folioNumber}`,
        relatedView: "logbook",
        relatedItemType: "logEntry",
        relatedItemId: entry.id,
        createdAt: entry.updatedAt.toISOString(),
        isRead: false,
      });
    }

    entry.signatureTasks?.forEach((task) => {
      const { urgency: signatureUrgency } = determineUrgency(entry.activityEndDate);
      notifications.push({
        id: `log-entry-sign-${task.id}`,
        type: "log_entry_assigned",
        urgency: signatureUrgency,
        message:
          signatureUrgency === "overdue"
            ? `Firma pendiente vencida: ${entry.title}`
            : `Firma pendiente: ${entry.title}`,
        sourceDescription: `Anotación #${entry.folioNumber}`,
        relatedView: "logbook",
        relatedItemType: "logEntry",
        relatedItemId: entry.id,
        createdAt: (task.assignedAt || task.createdAt).toISOString(),
        isRead: false,
      });
    });
  });

  const communications = await prisma.communication.findMany({
    where: {
      assigneeId: userId,
      status: CommunicationStatus.PENDIENTE,
      direction: CommunicationDirection.RECEIVED,
      requiresResponse: true,
    },
  });

  communications.forEach((communication) => {
    const dueReference =
      communication.responseDueDate ||
      communication.dueDate ||
      communication.sentDate;
    const { urgency, daysUntilDue } = determineUrgency(dueReference);

    let messagePrefix = "Comunicación asignada";
    if (urgency === "overdue") {
      messagePrefix = "Comunicación vencida";
    } else if (urgency === "due_soon" && typeof daysUntilDue === "number") {
      const suffix =
        daysUntilDue === 0
          ? "vence hoy"
          : `vence en ${daysUntilDue} día${daysUntilDue === 1 ? "" : "s"}`;
      messagePrefix = `Comunicación ${suffix}`;
    }

    notifications.push({
      id: `communication-${communication.id}`,
      type: "communication_assigned",
      urgency,
      message: `${messagePrefix}: ${communication.subject}`,
      sourceDescription: `Radicado ${communication.radicado}`,
      relatedView: "communications",
      relatedItemType: "communication",
      relatedItemId: communication.id,
      createdAt: (communication.assignedAt || communication.updatedAt).toISOString(),
      isRead: false,
    });
  });

  return notifications.sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
};
