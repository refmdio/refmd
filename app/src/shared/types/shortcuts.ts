export type ShortcutScope = 'global' | 'view' | 'editor' | 'vim' | 'panel';

export type ShortcutMode =
  | 'default'
  | 'vim-normal'
  | 'vim-insert'
  | 'vim-visual'
  | 'vim-command';

export type KeyChord = {
  key: string;
  shift?: boolean;
  alt?: boolean;
  ctrl?: boolean;
  meta?: boolean;
};

export type KeyBinding = KeyChord[];

export type ShortcutAction = {
  id: string;
  label: string;
  description?: string;
  category: string;
  scope: ShortcutScope;
  default: {
    mac?: KeyBinding[];
    windows?: KeyBinding[];
  };
  modes?: ShortcutMode[];
  allowInInputs?: boolean;
};

export type ShortcutAssignment = Partial<Record<ShortcutMode, KeyBinding[]>>;

export type ShortcutAssignmentMap = Record<string, ShortcutAssignment>;
