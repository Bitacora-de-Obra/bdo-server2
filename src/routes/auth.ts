import { Router, Request, Response } from "express";
import { PrismaClient, UserRole, AppRole } from "@prisma/client";
import bcrypt from "bcryptjs";
import { randomBytes, createHash } from "crypto";
import { CookieOptions } from "express";
import { authMiddleware, refreshAuthMiddleware, createAccessToken, createRefreshToken, AuthRequest } from "../middleware/auth";
import { sendEmailVerificationEmail, sendPasswordResetEmail, isEmailServiceConfigured } from "../services/email";
import { roleMap } from "../utils/enum-maps";
// Shared constants - will be imported from utils if needed

const router = Router();

// Shared dependencies injected from main app
export interface AuthRouterDeps {
  prisma: PrismaClient;
  isProduction: boolean;
  buildRefreshCookieOptions: (
    overrides?: Partial<CookieOptions>,
    includeMaxAge?: boolean
  ) => CookieOptions;
  validatePasswordStrength: (password: string) => Promise<string | null>;
}

export const createAuthRouter = (deps: AuthRouterDeps) => {
  const { prisma, isProduction, buildRefreshCookieOptions, validatePasswordStrength } = deps;

  const EMAIL_VERIFICATION_TOKEN_TTL_HOURS = Number(
    process.env.EMAIL_VERIFICATION_TOKEN_TTL_HOURS || 48
  );
  const PASSWORD_RESET_TOKEN_TTL_MINUTES = Number(
    process.env.PASSWORD_RESET_TOKEN_TTL_MINUTES || 60
  );

  const generateTokenValue = () => randomBytes(32).toString("hex");
  const hashToken = (token: string) =>
    createHash("sha256").update(token).digest("hex");

  const resolveProjectRole = (value?: string): UserRole | undefined => {
    if (!value) return undefined;
    if (roleMap[value]) {
      return roleMap[value];
    }
    const normalized = value.toUpperCase();
    if ((UserRole as any)[normalized]) {
      return normalized as UserRole;
    }
    return undefined;
  };

  // Register
  router.post("/register", async (req, res) => {
    const { email, password, fullName, projectRole, appRole } = req.body;

    if (!email || !password || !fullName || !projectRole || !appRole) {
      return res.status(400).json({ error: "Todos los campos son requeridos." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    try {
      const passwordError = await validatePasswordStrength(password);
      if (passwordError) {
        return res.status(400).json({ error: passwordError });
      }

      // Buscar usuario por email y tenantId (email es único por tenant)
      const tenantId = (req as any).tenant?.id;
      const existingUser = await prisma.user.findFirst({
        where: tenantId 
          ? { email: normalizedEmail, tenantId } as any
          : { email: normalizedEmail } as any,
      });

      if (existingUser) {
        return res.status(409).json({ error: "El email ya está registrado." });
      }

      if (!tenantId) {
        return res.status(400).json({ error: "No se pudo determinar el tenant." });
      }

      const hashedPassword = await bcrypt.hash(password, 12);

      const resolvedProjectRole =
        resolveProjectRole(projectRole) ?? UserRole.RESIDENT;
      const normalizedAppRole =
        typeof appRole === "string" ? appRole.toLowerCase() : "";
      const resolvedAppRole = Object.values(AppRole).includes(
        normalizedAppRole as AppRole
      )
        ? (normalizedAppRole as AppRole)
        : AppRole.viewer;

      const newUser = await prisma.user.create({
        data: {
          email: normalizedEmail,
          password: hashedPassword,
          fullName,
          projectRole: resolvedProjectRole,
          appRole: resolvedAppRole,
          status: "active",
          tokenVersion: 0,
          emailVerifiedAt: isEmailServiceConfigured() ? null : new Date(),
          tenantId,
        } as any,
      });

      let verificationEmailSent = false;

      if (isEmailServiceConfigured()) {
        const token = generateTokenValue();
        const tokenHash = hashToken(token);
        const expiresAt = new Date(
          Date.now() + EMAIL_VERIFICATION_TOKEN_TTL_HOURS * 60 * 60 * 1000
        );

        await prisma.emailVerificationToken.create({
          data: {
            userId: newUser.id,
            tokenHash,
            expiresAt,
          },
        });

        try {
          await sendEmailVerificationEmail({
            to: newUser.email,
            token,
            fullName: newUser.fullName,
          });
          verificationEmailSent = true;
        } catch (mailError) {
          console.error("No se pudo enviar el correo de verificación:", mailError);
        }
      }

      const { password: _, ...userWithoutPassword } = newUser;
      res.status(201).json({
        ...userWithoutPassword,
        verificationEmailSent,
      });
    } catch (error) {
      console.error("Error en registro:", error);
      res.status(500).json({ error: "Error al crear el usuario." });
    }
  });

  // Refresh token
  router.post("/refresh", refreshAuthMiddleware, async (req: AuthRequest, res) => {
    try {
      console.log('Refresh token request received');
      
      if (!req.user) {
        console.log('No user found in request');
        return res.status(401).json({ error: "No user found in request" });
      }

      console.log('User from token:', req.user);

      const user = await prisma.user.findUnique({
        where: { id: req.user.userId }
      });

      if (!user) {
        console.log('User not found in database');
        return res.status(401).json({ error: "User not found" });
      }

      console.log('User found in database');

      // Verificar token version
      if (user.tokenVersion !== req.user.tokenVersion) {
        console.log('Token version mismatch');
        return res.status(401).json({ error: "Token version mismatch" });
      }

      // Crear nuevo access token
      const accessToken = createAccessToken(user.id, user.tokenVersion);
      const refreshToken = createRefreshToken(user.id, user.tokenVersion);

      console.log('New tokens created');

      // Actualizar cookie de refresh token
      res.cookie('jid', refreshToken, buildRefreshCookieOptions());

      console.log('Refresh token cookie set');

      return res.json({ accessToken });
    } catch (error) {
      console.error("Error en refresh token:", error);
      res.status(500).json({ error: "Error al refrescar el token" });
    }
  });

  // Logout
  router.post("/logout", (req, res) => {
    res.clearCookie('jid', buildRefreshCookieOptions({}, false));
    res.json({ message: "Logged out successfully" });
  });

  // Login
  router.post("/login", async (req, res) => {
    try {
      const { email, password } = req.body;
      console.log('Login request received:', {
        email,
        hasPassword: Boolean(password),
      });

      if (!email || !password) {
        return res.status(400).json({ error: "Email y contraseña son requeridos." });
      }

      // Buscar usuario por email y tenantId (email es único por tenant)
      const tenantId = (req as any).tenant?.id;
      const user = await prisma.user.findFirst({
        where: tenantId 
          ? { email, tenantId } as any
          : { email } as any,
      });

      console.log('User found:', user ? 'yes' : 'no');

      if (!user) {
        return res.status(401).json({ error: "Credenciales inválidas." });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      console.log('Password valid:', isPasswordValid ? 'yes' : 'no');

      if (!isPasswordValid) {
        return res.status(401).json({ error: "Credenciales inválidas." });
      }

      if (user.status !== "active") {
        return res.status(403).json({ error: "La cuenta de usuario está inactiva." });
      }

      // Crear tokens de acceso y refresh
      const accessToken = createAccessToken(user.id, user.tokenVersion);
      const refreshToken = createRefreshToken(user.id, user.tokenVersion);

      console.log('Tokens created successfully');

      // Actualizar último login
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() }
      });

      // Enviar refresh token como cookie httpOnly
      res.cookie('jid', refreshToken, buildRefreshCookieOptions());

      const { password: _, ...userWithoutPassword } = user;
      
      console.log('Login successful, sending response');
      
      return res.json({ 
        accessToken,
        user: userWithoutPassword
      });

    } catch (error) {
      console.error("Error en login:", error);
      res.status(500).json({ error: "Error interno del servidor." });
    }
  });

  // Verify email
  router.post("/verify-email/:token", async (req, res) => {
    const { token } = req.params;

    if (!token) {
      return res.status(400).json({ error: "Token de verificación inválido." });
    }

    const tokenHash = hashToken(token);

    try {
      const verificationToken = await prisma.emailVerificationToken.findUnique({
        where: { tokenHash },
        include: { user: true },
      });

      if (!verificationToken || !verificationToken.user) {
        return res.status(400).json({ error: "Token no válido o ya utilizado." });
      }

      if (verificationToken.usedAt) {
        return res
          .status(400)
          .json({ error: "Este token ya fue utilizado previamente." });
      }

      if (verificationToken.expiresAt < new Date()) {
        return res.status(400).json({
          error: "El token de verificación ha expirado. Solicita uno nuevo.",
        });
      }

      await prisma.$transaction([
        prisma.user.update({
          where: { id: verificationToken.userId },
          data: {
            emailVerifiedAt: verificationToken.user.emailVerifiedAt ?? new Date(),
            status:
              verificationToken.user.status === "inactive"
                ? "active"
                : verificationToken.user.status,
          },
        }),
        prisma.emailVerificationToken.update({
          where: { id: verificationToken.id },
          data: { usedAt: new Date() },
        }),
        prisma.emailVerificationToken.deleteMany({
          where: {
            userId: verificationToken.userId,
            id: { not: verificationToken.id },
          },
        }),
      ]);

      res.json({ success: true });
    } catch (error) {
      console.error("Error al verificar el email:", error);
      res.status(500).json({ error: "Error al verificar el email." });
    }
  });

  // Forgot password
  router.post("/forgot-password", async (req, res) => {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ error: "Debes proporcionar el correo electrónico." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    try {
      // Buscar usuario por email y tenantId (email es único por tenant)
      const tenantId = (req as any).tenant?.id;
      const user = await prisma.user.findFirst({
        where: tenantId 
          ? { email: normalizedEmail, tenantId } as any
          : { email: normalizedEmail } as any,
      });

      if (user) {
        const token = generateTokenValue();
        const tokenHash = hashToken(token);
        const expiresAt = new Date(
          Date.now() + PASSWORD_RESET_TOKEN_TTL_MINUTES * 60 * 1000
        );

        await prisma.$transaction([
          prisma.passwordResetToken.deleteMany({
            where: { userId: user.id },
          }),
          prisma.passwordResetToken.create({
            data: {
              userId: user.id,
              tokenHash,
              expiresAt,
            },
          }),
        ]);

        if (isEmailServiceConfigured()) {
          try {
            await sendPasswordResetEmail({
              to: user.email,
              token,
              fullName: user.fullName,
            });
          } catch (mailError) {
            console.error(
              "No se pudo enviar el correo de restablecimiento:",
              mailError
            );
          }
        } else {
          console.warn(
            `Servicio de correo no configurado. Token de restablecimiento para ${user.email}: ${token}`
          );
        }
      }

      res.json({
        message:
          "Si el correo existe en nuestra base de datos, enviaremos instrucciones para restablecer la contraseña.",
      });
    } catch (error) {
      console.error("Error al solicitar restablecimiento de contraseña:", error);
      res.status(500).json({ error: "No fue posible procesar la solicitud." });
    }
  });

  // Reset password
  router.post("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    if (!token || !password) {
      return res
        .status(400)
        .json({ error: "Token y nueva contraseña son requeridos." });
    }

    try {
      const passwordError = await validatePasswordStrength(password);
      if (passwordError) {
        return res.status(400).json({ error: passwordError });
      }

      const tokenHash = hashToken(token);

      const resetToken = await prisma.passwordResetToken.findUnique({
        where: { tokenHash },
        include: { user: true },
      });

      if (!resetToken || !resetToken.user) {
        return res.status(400).json({ error: "Token inválido o no encontrado." });
      }

      if (resetToken.usedAt) {
        return res
          .status(400)
          .json({ error: "Este token ya fue utilizado, solicita uno nuevo." });
      }

      if (resetToken.expiresAt < new Date()) {
        return res.status(400).json({
          error: "El token ha expirado. Solicita un nuevo enlace de restablecimiento.",
        });
      }

      const hashedPassword = await bcrypt.hash(password, 12);

      await prisma.$transaction([
        prisma.user.update({
          where: { id: resetToken.userId },
          data: {
            password: hashedPassword,
            tokenVersion: resetToken.user.tokenVersion + 1,
            emailVerifiedAt: resetToken.user.emailVerifiedAt ?? new Date(),
          },
        }),
        prisma.passwordResetToken.update({
          where: { id: resetToken.id },
          data: { usedAt: new Date() },
        }),
        prisma.passwordResetToken.deleteMany({
          where: {
            userId: resetToken.userId,
            id: { not: resetToken.id },
          },
        }),
      ]);

      res.json({ success: true });
    } catch (error) {
      console.error("Error al restablecer la contraseña:", error);
      res
        .status(500)
        .json({ error: "No fue posible restablecer la contraseña." });
    }
  });

  // Change password (authenticated)
  router.post(
    "/change-password",
    authMiddleware,
    async (req: AuthRequest, res) => {
      const userId = req.user?.userId;
      const { oldPassword, newPassword } = req.body;

      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      if (!oldPassword || !newPassword) {
        return res.status(400).json({
          error: "Debes proporcionar la contraseña actual y la nueva.",
        });
      }

      try {
        const user = await prisma.user.findUnique({
          where: { id: userId },
        });

        if (!user) {
          return res.status(404).json({ error: "Usuario no encontrado." });
        }

        const isOldPasswordValid = await bcrypt.compare(
          oldPassword,
          user.password
        );

        if (!isOldPasswordValid) {
          return res
            .status(400)
            .json({ error: "La contraseña actual no es correcta." });
        }

        if (oldPassword === newPassword) {
          return res.status(400).json({
            error: "La nueva contraseña debe ser diferente a la anterior.",
          });
        }

        const passwordError = await validatePasswordStrength(newPassword);
        if (passwordError) {
          return res.status(400).json({ error: passwordError });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);

        await prisma.user.update({
          where: { id: user.id },
          data: {
            password: hashedPassword,
            tokenVersion: user.tokenVersion + 1,
          },
        });

        res.json({ success: true });
      } catch (error) {
        console.error("Error al cambiar la contraseña:", error);
        res
          .status(500)
          .json({ error: "No se pudo cambiar la contraseña en este momento." });
      }
    }
  );

  // Update profile
  router.put("/profile", authMiddleware, async (req: AuthRequest, res) => {
      const userId = req.user?.userId;
      const { fullName, avatarUrl } = req.body;
      console.log("Actualización de perfil solicitada por usuario:", userId, req.body);
      
      if (!userId) {
          return res.status(401).json({ error: "Usuario no autenticado." });
      }
      
      try {
          const updateData: { fullName?: string; avatarUrl?: string } = {};
          if (fullName) updateData.fullName = fullName;
          if (avatarUrl) updateData.avatarUrl = avatarUrl;

          if (Object.keys(updateData).length === 0) {
              return res.status(400).json({ error: "No se proporcionaron datos para actualizar." });
          }

          const updatedUser = await prisma.user.update({
              where: { id: userId },
              data: updateData,
              select: {
                  id: true,
                  fullName: true,
                  email: true,
                  projectRole: true,
                  avatarUrl: true,
                  appRole: true,
                  status: true,
                  lastLoginAt: true,
                  emailVerifiedAt: true,
              }
          });
          
          res.json(updatedUser);
          
      } catch (error) {
          console.error("Error al actualizar perfil:", error);
           if ((error as any)?.code === 'P2025') {
              return res.status(404).json({ error: "Usuario no encontrado." });
          }
          res.status(500).json({ error: "Error interno al actualizar el perfil." });
      }
  });

  // Get current user profile
  router.get("/me", authMiddleware, async (req: AuthRequest, res) => {
    const userId = req.user?.userId;

    if (!userId) {
      return res
        .status(401)
        .json({ error: "No se pudo identificar al usuario desde el token." });
    }

    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          fullName: true,
          email: true,
          projectRole: true,
          avatarUrl: true,
          appRole: true,
          status: true,
          lastLoginAt: true,
          emailVerifiedAt: true,
        },
      });

      if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      if (user.status !== "active") {
        return res
          .status(403)
          .json({ error: "La cuenta de usuario está inactiva." });
      }

      res.json(user);
    } catch (error) {
      console.error("Error al obtener datos del usuario (/api/auth/me):", error);
      res.status(500).json({ error: "Error interno del servidor." });
    }
  });

  return router;
};

