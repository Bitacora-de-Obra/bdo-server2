/**
 * Script para desactivar usuarios (quitar acceso directo sin borrarlos)
 * 
 * Uso:
 *   node scripts/deactivateUsers.js                    # Desactiva todos los usuarios
 *   node scripts/deactivateUsers.js --keep-admin        # Desactiva todos excepto admins
 *   node scripts/deactivateUsers.js --emails=email1,email2  # Desactiva usuarios específicos
 *   node scripts/deactivateUsers.js --activate          # Reactiva todos los usuarios
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  const args = process.argv.slice(2);
  const keepAdmin = args.includes('--keep-admin');
  const activate = args.includes('--activate');
  const emailsArg = args.find(arg => arg.startsWith('--emails='));
  const emails = emailsArg ? emailsArg.split('=')[1].split(',') : null;

  try {
    let whereClause = {};
    let status = activate ? 'active' : 'inactive';

    if (emails) {
      // Desactivar/activar usuarios específicos por email
      whereClause = {
        email: {
          in: emails.map(e => e.trim())
        }
      };
    } else if (keepAdmin) {
      // Desactivar todos excepto admins
      whereClause = {
        appRole: {
          not: 'ADMIN'
        }
      };
    }
    // Si no hay filtros, se aplica a todos los usuarios

    const result = await prisma.user.updateMany({
      where: whereClause,
      data: {
        status: status
      }
    });

    console.log(`\n✅ ${activate ? 'Activados' : 'Desactivados'}: ${result.count} usuario(s)`);
    
    if (emails) {
      console.log(`   Emails: ${emails.join(', ')}`);
    } else if (keepAdmin) {
      console.log(`   (Se mantuvieron activos los usuarios ADMIN)`);
    }

    // Mostrar resumen
    const activeCount = await prisma.user.count({
      where: { status: 'active' }
    });
    const inactiveCount = await prisma.user.count({
      where: { status: 'inactive' }
    });

    console.log(`\n📊 Resumen:`);
    console.log(`   Activos: ${activeCount}`);
    console.log(`   Inactivos: ${inactiveCount}`);
    console.log(`   Total: ${activeCount + inactiveCount}`);

  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();

