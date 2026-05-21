import {
  InputRule,
  inputRules,
  smartQuotes,
  textblockTypeInputRule,
  wrappingInputRule,
} from "prosemirror-inputrules";
import type { NodeType, Schema } from "prosemirror-model";
import type { Plugin } from "prosemirror-state";

function headingRule(nodeType: NodeType, maxLevel: number) {
  return textblockTypeInputRule(new RegExp(`^(#{1,${maxLevel}})\\s$`), nodeType, (match) => ({
    level: match[1].length,
  }));
}

function blockquoteRule(nodeType: NodeType) {
  return wrappingInputRule(/^\s*>\s$/, nodeType);
}

function orderedListRule(nodeType: NodeType) {
  return wrappingInputRule(
    /^(\d+)\.\s$/,
    nodeType,
    (match) => ({ order: +match[1] }),
    (match, node) => node.childCount + node.attrs.order === +match[1],
  );
}

function bulletListRule(nodeType: NodeType) {
  return wrappingInputRule(/^\s*([-+*])\s$/, nodeType);
}

function codeBlockRule(nodeType: NodeType) {
  return textblockTypeInputRule(/^```$/, nodeType);
}

function horizontalRuleRule(nodeType: NodeType) {
  return new InputRule(/^(?:---|\*\*\*|___)\s$/, (state, _match, start, end) => {
    return state.tr.replaceRangeWith(start, end, nodeType.create());
  });
}

export function markdownInputRules(schema: Schema): Plugin {
  const rules: InputRule[] = [...smartQuotes];

  if (schema.nodes.heading) {
    rules.push(headingRule(schema.nodes.heading, 6));
  }
  if (schema.nodes.blockquote) {
    rules.push(blockquoteRule(schema.nodes.blockquote));
  }
  if (schema.nodes.ordered_list) {
    rules.push(orderedListRule(schema.nodes.ordered_list));
  }
  if (schema.nodes.bullet_list) {
    rules.push(bulletListRule(schema.nodes.bullet_list));
  }
  if (schema.nodes.code_block) {
    rules.push(codeBlockRule(schema.nodes.code_block));
  }
  if (schema.nodes.horizontal_rule) {
    rules.push(horizontalRuleRule(schema.nodes.horizontal_rule));
  }

  return inputRules({ rules });
}
