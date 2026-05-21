defmodule RefMD.ArchitectureBoundaryTest do
  use ExUnit.Case, async: true

  @root Path.expand("../..", __DIR__)

  test "auth and sharing domain contexts do not reference the web layer" do
    violations =
      ["auth", "sharing"]
      |> Enum.flat_map(fn context ->
        @root
        |> Path.join("lib/refmd/#{context}/**/*.ex")
        |> Path.wildcard()
      end)
      |> Enum.flat_map(fn path ->
        source = File.read!(path)

        Regex.scan(~r/RefMDWeb\.[A-Za-z0-9_.]+/, source)
        |> Enum.map(fn [match] -> {relative(path), match} end)
      end)
      |> Enum.sort()

    assert violations == []
  end

  defp relative(path), do: Path.relative_to(path, @root)
end
