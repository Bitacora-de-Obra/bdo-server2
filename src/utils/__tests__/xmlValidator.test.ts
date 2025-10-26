import { validateCronogramaXml, CronogramaValidationError } from '../xmlValidator';

describe('validateCronogramaXml', () => {
  const sampleXml = `<?xml version="1.0" encoding="UTF-8"?>
  <Project>
    <Tasks>
      <Task>
        <UID>1</UID>
        <Name>Excavación general</Name>
        <Start>2024-07-21</Start>
        <Finish>2024-08-15</Finish>
        <PercentComplete>35</PercentComplete>
        <OutlineLevel>1</OutlineLevel>
      </Task>
    </Tasks>
  </Project>`;

  it('parses valid XML into task records', async () => {
    const tasks = await validateCronogramaXml(sampleXml);
    expect(tasks).toHaveLength(1);
    expect(tasks[0]).toMatchObject({
      id: '1',
      name: 'Excavación general',
      startDate: '2024-07-21',
    });
  });

  it('throws when XML is empty', async () => {
    await expect(validateCronogramaXml(''))
      .rejects.toBeInstanceOf(CronogramaValidationError);
  });

  it('throws when start date is missing', async () => {
    const badXml = sampleXml.replace('<Start>2024-07-21</Start>', '');
    await expect(validateCronogramaXml(badXml))
      .rejects.toThrow(/no tiene fecha de inicio/);
  });
});
