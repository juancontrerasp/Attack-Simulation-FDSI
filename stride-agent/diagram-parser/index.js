/**
 * ST-01.2 - Parser de diagramas en texto: Mermaid, PlantUML, C4
 * Extrae componentes y relaciones y los convierte en contexto textual para el agente STRIDE.
 */

// ─── Mermaid ────────────────────────────────────────────────────────────────

function parseMermaid(text) {
  const components = new Map();
  const edges = [];

  // Extraer etiquetas de nodos: A[Label], A(Label), A{Label}, A[(Label)]
  const nodeLabelRe = /\b([A-Za-z_][\w]*)\s*[\[({|]+([^\]})|]+)[\])}|]+/g;
  let m;
  while ((m = nodeLabelRe.exec(text)) !== null) {
    const id = m[1].trim();
    const label = m[2].trim().replace(/["']/g, '');
    if (label && !['graph', 'flowchart', 'sequenceDiagram', 'classDiagram', 'TD', 'LR', 'TB', 'BT', 'RL'].includes(id)) {
      components.set(id, label);
    }
  }

  // Extraer relaciones: A --> B, A -- label --> B, A ->> B
  const edgeRe = /\b([A-Za-z_][\w]*)\s*(?:--?>?>?|==>|\.\.>)\s*(?:\|([^|]+)\|\s*)?([A-Za-z_][\w]*)\b/g;
  while ((m = edgeRe.exec(text)) !== null) {
    edges.push({
      from: components.get(m[1]) || m[1],
      label: (m[2] || '').trim(),
      to: components.get(m[3]) || m[3]
    });
  }

  // Sequence diagram: participantes y mensajes
  const participantRe = /(?:participant|actor)\s+(\w+)(?:\s+as\s+(.+))?/gi;
  while ((m = participantRe.exec(text)) !== null) {
    const id = m[1].trim();
    const label = (m[2] || m[1]).trim();
    components.set(id, label);
  }

  const seqMsgRe = /([A-Za-z_]\w*)\s*->?>?\+?\s*([A-Za-z_]\w*)\s*:\s*(.+)/g;
  while ((m = seqMsgRe.exec(text)) !== null) {
    edges.push({
      from: components.get(m[1]) || m[1],
      label: m[3].trim(),
      to: components.get(m[2]) || m[2]
    });
  }

  return buildDescription('Mermaid', components, edges);
}

// ─── PlantUML ────────────────────────────────────────────────────────────────

function parsePlantUML(text) {
  const components = new Map();
  const edges = [];

  // Actores, componentes, bases de datos, etc.
  const declRe = /(?:actor|component|database|node|boundary|entity|usecase|rectangle|package|cloud|frame)\s+"?([^"\n]+)"?\s+(?:as\s+(\w+))?/gi;
  let m;
  while ((m = declRe.exec(text)) !== null) {
    const label = m[1].trim();
    const id = m[2] ? m[2].trim() : label.replace(/\s+/g, '_');
    components.set(id, label);
  }

  // Identificadores simples en declaraciones cortas: [ComponentName], :ActorName:
  const bracketRe = /\[([^\]]+)\]/g;
  while ((m = bracketRe.exec(text)) !== null) {
    const label = m[1].trim();
    components.set(label, label);
  }

  const colonRe = /:([^:\n]+):/g;
  while ((m = colonRe.exec(text)) !== null) {
    const label = m[1].trim();
    components.set(label, label);
  }

  // Relaciones: A --> B : label, A -> B : label
  const arrowRe = /(["\w\[\]:]+)\s*-+>+\s*(["\w\[\]:]+)(?:\s*:\s*(.+))?/g;
  while ((m = arrowRe.exec(text)) !== null) {
    const from = m[1].replace(/["\[\]:/]/g, '').trim();
    const to = m[2].replace(/["\[\]:/]/g, '').trim();
    edges.push({ from: components.get(from) || from, label: (m[3] || '').trim(), to: components.get(to) || to });
  }

  return buildDescription('PlantUML', components, edges);
}

// ─── C4 (Markdown blocks) ────────────────────────────────────────────────────

function parseC4(text) {
  const components = new Map();
  const edges = [];

  // Person(alias, "Label", "Description")
  // System/Container/Component(alias, "Label", "Description")
  const elemRe = /(?:Person|System|Container|Component|SystemDb|ContainerDb)(?:_Ext)?\s*\(\s*(\w+)\s*,\s*"([^"]+)"/gi;
  let m;
  while ((m = elemRe.exec(text)) !== null) {
    components.set(m[1].trim(), m[2].trim());
  }

  // Rel(from, to, "label") / BiRel(from, to, "label")
  const relRe = /(?:Bi)?Rel(?:_\w+)?\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*"([^"]*)"/gi;
  while ((m = relRe.exec(text)) !== null) {
    edges.push({
      from: components.get(m[1]) || m[1],
      label: m[3].trim(),
      to: components.get(m[2]) || m[2]
    });
  }

  return buildDescription('C4', components, edges);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildDescription(type, components, edges) {
  const compList = [...components.values()].filter(Boolean);
  const lines = [`Diagrama ${type} con ${compList.length} componentes y ${edges.length} relaciones.`];

  if (compList.length > 0) {
    lines.push(`Componentes: ${compList.join(', ')}.`);
  }

  if (edges.length > 0) {
    const edgeLines = edges.slice(0, 20).map(e => {
      const label = e.label ? ` (${e.label})` : '';
      return `${e.from} → ${e.to}${label}`;
    });
    lines.push(`Flujos de datos: ${edgeLines.join('; ')}.`);
  }

  return lines.join('\n');
}

// ─── Detección de bloques Mermaid en Markdown ────────────────────────────────

function extractMermaidBlocks(markdownText) {
  const blocks = [];
  const re = /```mermaid\s*([\s\S]*?)```/gi;
  let m;
  while ((m = re.exec(markdownText)) !== null) {
    blocks.push(m[1].trim());
  }
  return blocks;
}

// ─── API pública ─────────────────────────────────────────────────────────────

/**
 * Parsea un archivo de diagrama y retorna una descripción textual estructurada.
 * @param {string} filePath  Ruta al archivo
 * @param {string} content   Contenido del archivo (si ya fue leído)
 * @returns {{ diagramType: string, description: string, componentCount: number }}
 */
function parseDiagramFile(filePath, content) {
  const ext = filePath.split('.').pop().toLowerCase();

  if (ext === 'mmd') {
    const desc = parseMermaid(content);
    return { diagramType: 'mermaid', description: desc, componentCount: (desc.match(/componentes?:/i) || [''])[0] };
  }

  if (ext === 'puml' || ext === 'plantuml') {
    const desc = parsePlantUML(content);
    return { diagramType: 'plantuml', description: desc, componentCount: 0 };
  }

  // Markdown: buscar bloques mermaid y bloques C4
  if (ext === 'md') {
    const mermaidBlocks = extractMermaidBlocks(content);
    const c4Desc = parseC4(content);
    const mermaidDescs = mermaidBlocks.map(b => parseMermaid(b));

    const descriptions = [...mermaidDescs, c4Desc].filter(d => !d.startsWith('Diagrama') || d.includes('relaciones'));

    const combined = descriptions.length > 0
      ? descriptions.join('\n\n')
      : 'Archivo Markdown sin bloques de diagrama reconocibles.';

    return { diagramType: 'markdown', description: combined, componentCount: 0 };
  }

  // Intento generico: si contiene @startuml es PlantUML, si contiene graph es Mermaid
  if (content.includes('@startuml')) {
    return { diagramType: 'plantuml', description: parsePlantUML(content), componentCount: 0 };
  }
  if (/\bgraph\s+(TD|LR|TB|BT|RL)\b/i.test(content) || /\bflowchart\b/i.test(content)) {
    return { diagramType: 'mermaid', description: parseMermaid(content), componentCount: 0 };
  }

  return { diagramType: 'unknown', description: content.slice(0, 2000), componentCount: 0 };
}

/**
 * Construye el contexto arquitectónico desde la descripción del diagrama.
 */
function buildDiagramContext(filePath, parseResult) {
  return [
    `## Diagrama de arquitectura: ${filePath}`,
    `Tipo: ${parseResult.diagramType}`,
    '',
    parseResult.description
  ].join('\n');
}

module.exports = { parseDiagramFile, buildDiagramContext, parseMermaid, parsePlantUML, parseC4 };
