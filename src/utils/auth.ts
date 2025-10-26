import prisma from '../prisma';

export async function incrementTokenVersion(userId: string): Promise<void> {
  await prisma.user.update({
    where: { id: userId },
    data: {
      tokenVersion: {
        increment: 1
      }
    }
  });
}

export async function validateRefreshToken(userId: string, tokenVersion: number): Promise<boolean> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { tokenVersion: true }
  });

  if (!user) {
    return false;
  }

  return user.tokenVersion === tokenVersion;
}


