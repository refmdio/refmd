import { describe, it, expect } from 'vitest'

import { extractTags, extractTagsPreserveCase } from '@/shared/lib/tags'

describe('extractTags', () => {
  describe('basic extraction', () => {
    it('should extract a single tag', () => {
      expect(extractTags('Hello #world')).toEqual(['world'])
    })

    it('should extract multiple tags', () => {
      const tags = extractTags('Hello #world and #foo')
      expect(tags).toContain('world')
      expect(tags).toContain('foo')
      expect(tags).toHaveLength(2)
    })

    it('should extract tags with underscores', () => {
      expect(extractTags('#foo_bar')).toEqual(['foo_bar'])
    })

    it('should extract tags with numbers', () => {
      expect(extractTags('#tag123')).toEqual(['tag123'])
    })

    it('should normalize tags to lowercase', () => {
      expect(extractTags('#Hello #WORLD #FooBar')).toEqual(['hello', 'world', 'foobar'])
    })

    it('should deduplicate tags (case-insensitive)', () => {
      expect(extractTags('#hello #Hello #HELLO')).toEqual(['hello'])
    })

    it('should extract tag at start of text', () => {
      expect(extractTags('#start of text')).toEqual(['start'])
    })

    it('should extract tag at end of text', () => {
      expect(extractTags('end of text #end')).toEqual(['end'])
    })
  })

  describe('preceding character checks', () => {
    it('should ignore tag preceded by alphanumeric', () => {
      expect(extractTags('word#tag')).toEqual([])
      expect(extractTags('123#tag')).toEqual([])
    })

    it('should ignore tag preceded by slash', () => {
      expect(extractTags('path/#tag')).toEqual([])
      expect(extractTags('https://example.com#anchor')).toEqual([])
    })

    it('should ignore tag preceded by colon', () => {
      expect(extractTags('prefix:#tag')).toEqual([])
    })

    it('should ignore tag preceded by at sign', () => {
      expect(extractTags('email@domain.com#tag')).toEqual([])
    })

    it('should ignore tag preceded by dot', () => {
      expect(extractTags('file.#tag')).toEqual([])
    })

    it('should ignore tag preceded by hyphen', () => {
      expect(extractTags('word-#tag')).toEqual([])
    })

    it('should ignore tag preceded by underscore', () => {
      expect(extractTags('word_#tag')).toEqual([])
    })

    it('should ignore tag preceded by plus', () => {
      expect(extractTags('word+#tag')).toEqual([])
    })

    it('should ignore tag preceded by tilde', () => {
      expect(extractTags('word~#tag')).toEqual([])
    })

    it('should ignore tag preceded by equals', () => {
      expect(extractTags('word=#tag')).toEqual([])
    })

    it('should ignore tag preceded by question mark', () => {
      expect(extractTags('param?#tag')).toEqual([])
    })

    it('should ignore tag preceded by ampersand', () => {
      expect(extractTags('param&#tag')).toEqual([])
    })

    it('should ignore tag preceded by percent', () => {
      expect(extractTags('100%#tag')).toEqual([])
    })

    it('should extract tag preceded by space', () => {
      expect(extractTags('word #tag')).toEqual(['tag'])
    })

    it('should extract tag preceded by newline', () => {
      expect(extractTags('word\n#tag')).toEqual(['tag'])
    })

    it('should extract tag preceded by tab', () => {
      expect(extractTags('word\t#tag')).toEqual(['tag'])
    })

    it('should extract tag preceded by parenthesis', () => {
      expect(extractTags('(#tag)')).toEqual(['tag'])
    })

    it('should extract tag preceded by bracket', () => {
      expect(extractTags('[#tag]')).toEqual(['tag'])
    })
  })

  describe('code block exclusion', () => {
    it('should ignore tags inside fenced code blocks', () => {
      const markdown = '```\n#code_tag\n```\n#real_tag'
      expect(extractTags(markdown)).toEqual(['real_tag'])
    })

    it('should ignore tags inside inline code', () => {
      const markdown = 'Check `#inline_code` and #real_tag'
      expect(extractTags(markdown)).toEqual(['real_tag'])
    })

    it('should handle multiple code blocks', () => {
      const markdown = '```\n#tag1\n```\n#real1\n```js\n#tag2\n```\n#real2'
      const tags = extractTags(markdown)
      expect(tags).toContain('real1')
      expect(tags).toContain('real2')
      expect(tags).not.toContain('tag1')
      expect(tags).not.toContain('tag2')
    })

    it('should handle code block with language specifier', () => {
      const markdown = '```typescript\nconst x = "#not_a_tag";\n```\n#real_tag'
      expect(extractTags(markdown)).toEqual(['real_tag'])
    })
  })

  describe('length limits', () => {
    it('should extract tags up to 50 characters', () => {
      const tag50 = 'a'.repeat(50)
      expect(extractTags(`#${tag50}`)).toEqual([tag50])
    })

    it('should truncate tags longer than 50 characters', () => {
      const tag60 = 'a'.repeat(60)
      const expected = 'a'.repeat(50)
      expect(extractTags(`#${tag60}`)).toEqual([expected])
    })
  })

  describe('edge cases', () => {
    it('should return empty array for empty string', () => {
      expect(extractTags('')).toEqual([])
    })

    it('should return empty array for null/undefined', () => {
      expect(extractTags(null as unknown as string)).toEqual([])
      expect(extractTags(undefined as unknown as string)).toEqual([])
    })

    it('should return empty array for string without tags', () => {
      expect(extractTags('Hello world')).toEqual([])
    })

    it('should return empty array for lone hash', () => {
      expect(extractTags('#')).toEqual([])
      expect(extractTags('# ')).toEqual([])
    })

    it('should handle consecutive tags', () => {
      const tags = extractTags('#tag1#tag2')
      // First tag is valid, second is preceded by alphanumeric
      expect(tags).toEqual(['tag1'])
    })

    it('should handle tags separated by space', () => {
      const tags = extractTags('#tag1 #tag2')
      expect(tags).toContain('tag1')
      expect(tags).toContain('tag2')
    })

    it('should handle markdown headings (not tags)', () => {
      // # followed by space is a heading, not a tag
      expect(extractTags('# Heading')).toEqual([])
      expect(extractTags('## Another Heading')).toEqual([])
    })

    it('should handle special characters in tag body', () => {
      // Only alphanumeric and underscore are valid
      expect(extractTags('#tag-with-dash')).toEqual(['tag'])
      expect(extractTags('#tag.with.dot')).toEqual(['tag'])
    })
  })
})

describe('extractTagsPreserveCase', () => {
  it('should preserve original casing of first occurrence', () => {
    expect(extractTagsPreserveCase('#Hello #WORLD')).toEqual(['Hello', 'WORLD'])
  })

  it('should deduplicate based on lowercase but keep first casing', () => {
    expect(extractTagsPreserveCase('#Hello #hello #HELLO')).toEqual(['Hello'])
  })

  it('should work with mixed case tags', () => {
    const tags = extractTagsPreserveCase('#FooBar #another #FooBar')
    expect(tags).toEqual(['FooBar', 'another'])
  })
})
