/**
 * Yjs Collab Plugins for ProseMirror
 *
 * Bundles ySyncPlugin, yCursorPlugin, yUndoPlugin, and bridgeSyncPlugin
 * via @pm-cm/yjs for the dual-editor setup.
 */

import type * as Y from 'yjs'
import type { Awareness } from 'y-protocols/awareness'
import type { Schema, Node } from 'prosemirror-model'
import type { Plugin } from 'prosemirror-state'
import {
  createYjsBridge,
  createCollabPlugins,
  type YjsBridgeHandle,
} from '@pm-cm/yjs'
import {
  markdownToProseMirrorDoc,
  proseMirrorDocToMarkdown,
  normalizeMarkdown,
} from './markdown-convert'

function createSerialize(_schema: Schema) {
  return (doc: Node): string => {
    return proseMirrorDocToMarkdown(doc)
  }
}

function createParse(schema: Schema) {
  return (text: string): Node => {
    return markdownToProseMirrorDoc(text, schema)
  }
}

export interface CollabSetup {
  plugins: Plugin[]
  doc: Node
  bridge: YjsBridgeHandle
  destroy: () => void
}

export function setupCollabPlugins(opts: {
  yDoc: Y.Doc
  schema: Schema
  awareness: Awareness
  textFieldName?: string
  xmlFieldName?: string
}): CollabSetup {
  const {
    yDoc,
    schema,
    awareness,
    textFieldName = 'content',
    xmlFieldName = 'prosemirror',
  } = opts

  const sharedText = yDoc.getText(textFieldName)
  const sharedProseMirror = yDoc.getXmlFragment(xmlFieldName)

  const serialize = createSerialize(schema)
  const parse = createParse(schema)

  const bridge = createYjsBridge({
    doc: yDoc,
    sharedText,
    sharedProseMirror,
    schema,
    serialize,
    parse,
    normalize: normalizeMarkdown,
    skipOrigins: new Set<unknown>(['remote']),
  })

  const { plugins, doc } = createCollabPlugins(schema, {
    sharedProseMirror,
    awareness,
    bridge,
    sharedText,
    cursorSync: true,
    serialize,
  })

  return {
    plugins,
    doc,
    bridge,
    destroy: () => {
      bridge.dispose()
    },
  }
}
