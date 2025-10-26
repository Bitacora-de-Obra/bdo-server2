import winston from 'winston';

const level = process.env.LOG_LEVEL || 'info';

export const logger = winston.createLogger({
  level,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf(({ level, message, timestamp, ...meta }) => {
          const metaString = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
          return `${timestamp} [${level}] ${message}${metaString}`;
        })
      ),
    }),
  ],
});

if (process.env.LOG_TO_FILE === 'true') {
  logger.add(
    new winston.transports.File({
      filename: process.env.LOG_FILE_PATH || 'logs/app.log',
      format: winston.format.json(),
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5,
    })
  );
}
