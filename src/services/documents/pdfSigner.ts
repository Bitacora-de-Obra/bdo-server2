import { PDFDocument, PDFEmbeddedPage } from "pdf-lib";

interface SignaturePosition {
  page?: number;
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  baseline?: boolean;
  baselineRatio?: number;
}

interface ApplySignatureInput {
  originalPdf: Buffer;
  signature: {
    buffer: Buffer;
    mimeType: string;
  };
  position?: SignaturePosition;
}

const DEFAULT_SIGNATURE_WIDTH = 180;
const DEFAULT_MARGIN = 48;

export const applySignatureToPdf = async ({
  originalPdf,
  signature,
  position,
}: ApplySignatureInput): Promise<Buffer> => {
  const pdfDoc = await PDFDocument.load(originalPdf);
  const pageCount = pdfDoc.getPageCount();
  if (pageCount === 0) {
    throw new Error("El PDF no contiene páginas.");
  }

  const targetPageIndex = Math.min(
    Math.max(position?.page ?? pageCount - 1, 0),
    pageCount - 1
  );
  const page = pdfDoc.getPage(targetPageIndex);
  const pageWidth = page.getWidth();
  const pageHeight = page.getHeight();

  const width = Math.min(
    position?.width ?? DEFAULT_SIGNATURE_WIDTH,
    pageWidth - DEFAULT_MARGIN
  );

  let height = position?.height;

  const x =
    position?.x ??
    Math.max(pageWidth - width - DEFAULT_MARGIN, DEFAULT_MARGIN);
  const rawY = position?.y ?? DEFAULT_MARGIN;

  if (signature.mimeType === "application/pdf") {
    const embeddedPages = (await pdfDoc.embedPdf(signature.buffer, [0])) as PDFEmbeddedPage[];
    const embeddedPage = embeddedPages[0];
    const signatureWidth = embeddedPage.width;
    const signatureHeight = embeddedPage.height;
    const scale = width / signatureWidth;
    const scaledHeight = signatureHeight * scale;
    height = height ?? scaledHeight;

    const finalHeight = height ?? scaledHeight;
    const baselineRatio = position?.baselineRatio ?? 0.65;
    let y = position?.baseline
      ? rawY - finalHeight * baselineRatio
      : rawY;
    y = Math.max(
      DEFAULT_MARGIN,
      Math.min(y, pageHeight - finalHeight - DEFAULT_MARGIN)
    );
    page.drawPage(embeddedPage, {
      x,
      y,
      xScale: width / signatureWidth,
      yScale: finalHeight / signatureHeight,
    });
  } else if (signature.mimeType === "image/png") {
    const embedded = await pdfDoc.embedPng(signature.buffer);
    const embedWidth = embedded.width;
    const embedHeight = embedded.height;
    const scale = width / embedWidth;
    const scaledHeight = embedHeight * scale;
    const finalHeight = height ?? scaledHeight;
    const baselineRatio = position?.baselineRatio ?? 0.65;
    let y = position?.baseline
      ? rawY - finalHeight * baselineRatio
      : rawY;
    y = Math.max(
      DEFAULT_MARGIN,
      Math.min(y, pageHeight - finalHeight - DEFAULT_MARGIN)
    );
    page.drawImage(embedded, {
      x,
      y,
      width,
      height: finalHeight,
    });
  } else if (
    signature.mimeType === "image/jpeg" ||
    signature.mimeType === "image/jpg"
  ) {
    const embedded = await pdfDoc.embedJpg(signature.buffer);
    const embedWidth = embedded.width;
    const embedHeight = embedded.height;
    const scale = width / embedWidth;
    const scaledHeight = embedHeight * scale;
    const finalHeight = height ?? scaledHeight;
    const baselineRatio = position?.baselineRatio ?? 0.65;
    let y = position?.baseline
      ? rawY - finalHeight * baselineRatio
      : rawY;
    y = Math.max(
      DEFAULT_MARGIN,
      Math.min(y, pageHeight - finalHeight - DEFAULT_MARGIN)
    );
    page.drawImage(embedded, {
      x,
      y,
      width,
      height: finalHeight,
    });
  } else {
    throw new Error(
      `Tipo de archivo de firma no soportado: ${signature.mimeType}`
    );
  }

  const signedPdfBytes = await pdfDoc.save();
  return Buffer.from(signedPdfBytes);
};
