/**
 * Tests for client-side Markdown renderer
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { renderMarkdown } from '../renderer'
import { resetPlaceholderCounter } from '../plugins'

describe('Markdown Renderer', () => {
  beforeEach(() => {
    resetPlaceholderCounter()
  })

  describe('Basic Markdown', () => {
    it('should render paragraphs', async () => {
      const result = await renderMarkdown('Hello, world!')
      expect(result.html).toContain('<p')
      expect(result.html).toContain('Hello, world!')
    })

    it('should render headings', async () => {
      const result = await renderMarkdown('# Heading 1\n## Heading 2')
      expect(result.html).toContain('<h1')
      expect(result.html).toContain('Heading 1')
      expect(result.html).toContain('<h2')
      expect(result.html).toContain('Heading 2')
    })

    it('should render links', async () => {
      const result = await renderMarkdown('[Example](https://example.com)')
      expect(result.html).toContain('<a')
      expect(result.html).toContain('href="https://example.com"')
      expect(result.html).toContain('Example')
    })

    it('should render code blocks', async () => {
      const result = await renderMarkdown('```javascript\nconst x = 1;\n```')
      expect(result.html).toContain('<code')
    })
  })

  describe('GFM Features', () => {
    it('should render tables', async () => {
      const md = `| A | B |
|---|---|
| 1 | 2 |`
      const result = await renderMarkdown(md)
      expect(result.html).toContain('<table')
      expect(result.html).toContain('<th')
    })

    it('should render strikethrough', async () => {
      const result = await renderMarkdown('~~deleted~~')
      expect(result.html).toContain('<del')
      expect(result.html).toContain('deleted')
    })

    it('should render tasklist', async () => {
      const result = await renderMarkdown('- [x] Done\n- [ ] Todo')
      expect(result.html).toContain('type="checkbox"')
    })
  })

  describe('Wikilinks', () => {
    it('should transform [[target]] to refmd-wikilink', async () => {
      const result = await renderMarkdown('Link to [[document]]')
      expect(result.html).toContain('<refmd-wikilink')
      expect(result.html).toContain('target="document"')
      expect(result.html).toContain('variant="embed"')
    })

    it('should transform [[target|alias]] with alias', async () => {
      const result = await renderMarkdown('Link to [[doc-id|My Document]]')
      expect(result.html).toContain('<refmd-wikilink')
      expect(result.html).toContain('target="doc-id"')
      expect(result.html).toContain('My Document')
    })

    it('should transform [[target|alias|inline]] with inline variant', async () => {
      const result = await renderMarkdown('Link to [[doc-id|alias|inline]]')
      expect(result.html).toContain('variant="inline"')
    })

    it('should transform #wiki:target syntax', async () => {
      const result = await renderMarkdown('Link to #wiki:document')
      expect(result.html).toContain('<refmd-wikilink')
      expect(result.html).toContain('target="document"')
    })
  })

  describe('Hashtags', () => {
    it('should transform #tag to anchor', async () => {
      const result = await renderMarkdown('This is #test tag')
      expect(result.html).toContain('<a href="#tag-test" class="hashtag">')
      expect(result.html).toContain('#test')
    })

    it('should not transform hashtags in URLs', async () => {
      const result = await renderMarkdown('Visit https://example.com#section')
      expect(result.html).not.toContain('class="hashtag"')
    })

    it('should not transform hashtags after alphanumeric', async () => {
      const result = await renderMarkdown('Issue#123')
      expect(result.html).not.toContain('class="hashtag"')
    })
  })

  describe('Mentions', () => {
    it('should transform #mention:user to anchor', async () => {
      const result = await renderMarkdown('Hello #mention:john')
      expect(result.html).toContain('<a href="#mention:john" class="mention"')
      expect(result.html).toContain('data-mention-target="john"')
    })
  })

  describe('Placeholders', () => {
    it('should convert code blocks to placeholders when kind matches', async () => {
      const result = await renderMarkdown('```mermaid\ngraph TD\n```', {
        placeholderKinds: ['mermaid'],
      })
      expect(result.html).toContain('data-refmd-placeholder="true"')
      expect(result.html).toContain('data-placeholder-kind="mermaid"')
      expect(result.placeholders).toHaveLength(1)
      expect(result.placeholders[0].kind).toBe('mermaid')
    })

    it('should not convert code blocks when kind does not match', async () => {
      const result = await renderMarkdown('```javascript\nconst x = 1;\n```', {
        placeholderKinds: ['mermaid'],
      })
      expect(result.html).not.toContain('data-refmd-placeholder')
      expect(result.placeholders).toHaveLength(0)
    })
  })

  describe('Sourcepos', () => {
    it('should add data-sourcepos attributes', async () => {
      const result = await renderMarkdown('# Heading')
      expect(result.html).toContain('data-sourcepos')
    })
  })

  describe('Hash', () => {
    it('should return consistent hash for same input', async () => {
      const result1 = await renderMarkdown('Hello')
      const result2 = await renderMarkdown('Hello')
      expect(result1.hash).toBe(result2.hash)
    })

    it('should return different hash for different input', async () => {
      const result1 = await renderMarkdown('Hello')
      const result2 = await renderMarkdown('World')
      expect(result1.hash).not.toBe(result2.hash)
    })
  })

  describe('Sanitization', () => {
    it('should sanitize script tags by default', async () => {
      const result = await renderMarkdown('<script>alert("xss")</script>')
      expect(result.html).not.toContain('<script')
    })

    it('should allow safe HTML when sanitize is disabled', async () => {
      const result = await renderMarkdown('<div class="custom">Content</div>', {
        sanitize: false,
      })
      expect(result.html).toContain('<div class="custom">')
    })
  })
})

describe('Syntax Highlighting', () => {
  it('should highlight code when highlight feature is enabled', async () => {
    const result = await renderMarkdown('```javascript\nconst x = 1;\n```', {
      features: ['gfm', 'highlight'],
    })
    expect(result.html).toContain('not-prose')
    expect(result.html).toContain('shiki')
    expect(result.html).toContain('<code>')
  })
})
