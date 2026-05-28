import { describe, expect, it } from "vitest";
import {
  auxiliaryPanePreferredLocation,
  workspaceTileCanOpenFromDocumentMenu,
  type AuxiliaryPaneConfig,
  type WorkspaceTileConfig,
} from "./app";

describe("workspace app surface helpers", () => {
  it("allows only document-menu document workspace tiles in a document tab menu", () => {
    const tile = (input: Pick<WorkspaceTileConfig, "scope" | "preferredOpen">) => input;

    expect(
      workspaceTileCanOpenFromDocumentMenu(
        tile({ scope: "document", preferredOpen: "document_menu" }),
      ),
    ).toBe(true);
    expect(
      workspaceTileCanOpenFromDocumentMenu(tile({ scope: "document", preferredOpen: "manual" })),
    ).toBe(false);
    expect(
      workspaceTileCanOpenFromDocumentMenu(tile({ scope: "document", preferredOpen: "command" })),
    ).toBe(false);
    expect(
      workspaceTileCanOpenFromDocumentMenu(
        tile({ scope: "workspace", preferredOpen: "document_menu" }),
      ),
    ).toBe(false);
  });

  it("preserves document-adjacent auxiliary pane locations", () => {
    const pane = (allowedLocations: AuxiliaryPaneConfig["allowedLocations"]) =>
      ({
        id: allowedLocations[0],
        title: allowedLocations[0],
        allowedLocations,
        render: () => undefined,
      }) satisfies AuxiliaryPaneConfig;

    expect(auxiliaryPanePreferredLocation(pane(["left"]))).toBe("left");
    expect(auxiliaryPanePreferredLocation(pane(["right"]))).toBe("right");
    expect(auxiliaryPanePreferredLocation(pane(["document_left", "left"]))).toBe("document_left");
    expect(auxiliaryPanePreferredLocation(pane(["document_right", "right"]))).toBe(
      "document_right",
    );
  });
});
