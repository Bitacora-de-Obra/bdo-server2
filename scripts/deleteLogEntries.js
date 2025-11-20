/* eslint-disable no-console */
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function deleteLogEntries() {
  const filter = {}; // TODO ajustar filtro si no quieres borrar todas
  try {
    const entries = await prisma.logEntry.findMany({
      where: filter,
      select: { id: true, folioNumber: true, title: true },
    });

    if (!entries.length) {
      console.log("No se encontraron bitácoras que coincidan con el filtro.");
      return;
    }

    console.log(`Se encontraron ${entries.length} bitácoras.`);
    entries.forEach((entry) =>
      console.log(`- ${entry.id} | Folio ${entry.folioNumber} | ${entry.title}`)
    );

    const logEntryIds = entries.map((entry) => entry.id);

    const deletedAttachments = await prisma.attachment.deleteMany({
      where: { logEntryId: { in: logEntryIds } },
    });
    const deletedComments = await prisma.comment.deleteMany({
      where: { logEntryId: { in: logEntryIds } },
    });
    const deletedSignatures = await prisma.signature.deleteMany({
      where: { logEntryId: { in: logEntryIds } },
    });
    const deletedHistory = await prisma.logEntryHistory.deleteMany({
      where: { logEntryId: { in: logEntryIds } },
    });
    const deletedSignatureTasks = await prisma.logEntrySignatureTask.deleteMany({
      where: { logEntryId: { in: logEntryIds } },
    });
    const deletedReviewTasks = await prisma.logEntryReviewTask.deleteMany({
      where: { logEntryId: { in: logEntryIds } },
    });
    const deletedEntries = await prisma.logEntry.deleteMany({
      where: { id: { in: logEntryIds } },
    });

    console.log("Resumen de eliminaciones:");
    console.table({
      attachments: deletedAttachments.count,
      comments: deletedComments.count,
      signatures: deletedSignatures.count,
      history: deletedHistory.count,
      signatureTasks: deletedSignatureTasks.count,
      reviewTasks: deletedReviewTasks.count,
      logEntries: deletedEntries.count,
    });
  } catch (error) {
    console.error("Error eliminando bitácoras:", error);
  } finally {
    await prisma.$disconnect();
  }
}

deleteLogEntries();

