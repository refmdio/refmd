/**
 * Mosaic Document Workspace
 *
 * Renders Editor and Preview panels in a resizable tile layout using react-mosaic.
 */

import { useCallback } from 'react'
import { Mosaic, MosaicWindow, MosaicNode, MosaicBranch } from 'react-mosaic-component'
import { MoreVertical, FileText, SplitSquareHorizontal, SplitSquareVertical, RefreshCw, X } from 'lucide-react'
import {
  useDocumentWorkspace,
  decodePanelId,
} from '../model/DocumentWorkspaceContext'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/shared/ui/dropdown-menu'
import { EditorPanel } from './EditorPanel'
import { PreviewPanel } from './PreviewPanel'
import { DocumentPresenceAvatars } from '@/features/document-edit'

import 'react-mosaic-component/react-mosaic-component.css'
import './mosaic-theme.css'

export function MosaicDocumentWorkspace() {
  const {
    openDocuments,
    mosaicState,
    focusedDocumentId,
    focusedPanelType,
    closePanel,
    splitPanel,
    switchPanelType,
    setMosaicState,
    setFocusedDocumentId,
    setFocusedPanelType,
  } = useDocumentWorkspace()

  const handleChange = useCallback(
    (newNode: MosaicNode<string> | null) => {
      setMosaicState(newNode)
    },
    [setMosaicState]
  )

  const renderTile = (panelId: string, path: MosaicBranch[]) => {
    const panel = decodePanelId(panelId)
    if (!panel) return null

    const doc = openDocuments.get(panel.documentId)
    const title = doc?.title ?? 'Loading...'
    const isEditor = panel.type === 'editor'
    const showCursors =
      panel.documentId === focusedDocumentId &&
      panel.type === (focusedPanelType ?? 'editor')
    const focusPanel = () => {
      setFocusedDocumentId(panel.documentId)
      setFocusedPanelType(panel.type)
    }

    return (
      <MosaicWindow<string>
        path={path}
        title={`${title} - ${isEditor ? 'Markdown' : 'WYSIWYG'}`}
        toolbarControls={[
          <DocumentPresenceAvatars key="presence" documentId={panel.documentId} />,
          <DropdownMenu key="menu">
            <DropdownMenuTrigger asChild>
              <button className="p-1 hover:bg-muted rounded">
                <MoreVertical className="w-4 h-4" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => splitPanel(panelId, 'row')}>
                <SplitSquareHorizontal className="w-4 h-4 mr-2" />
                Split Horizontal
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => splitPanel(panelId, 'column')}>
                <SplitSquareVertical className="w-4 h-4 mr-2" />
                Split Vertical
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => switchPanelType(panelId)}>
                <RefreshCw className="w-4 h-4 mr-2" />
                Switch to {isEditor ? 'WYSIWYG' : 'Markdown'}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => closePanel(panelId)}>
                <X className="w-4 h-4 mr-2" />
                Close
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>,
        ]}
        onDragStart={focusPanel}
      >
        <div
          className="h-full"
          // Capture phase avoids editor internals suppressing bubble events.
          onFocusCapture={focusPanel}
          onMouseDownCapture={focusPanel}
        >
          {isEditor ? (
            <EditorPanel documentId={panel.documentId} showCursors={showCursors} />
          ) : (
            <PreviewPanel documentId={panel.documentId} showCursors={showCursors} />
          )}
        </div>
      </MosaicWindow>
    )
  }

  if (!mosaicState) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <div className="text-center">
          <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
          <p>No documents open</p>
          <p className="text-sm">Select a document from the sidebar</p>
        </div>
      </div>
    )
  }

  return (
    <Mosaic<string>
      renderTile={renderTile}
      value={mosaicState}
      onChange={handleChange}
      className="mosaic-blueprint-theme"
    />
  )
}
