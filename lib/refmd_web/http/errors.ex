defmodule RefMDWeb.Http.Errors do
  @moduledoc false

  @doc "Check if a changeset has a unique constraint error."
  def has_unique_constraint_error?(%Ecto.Changeset{} = changeset) do
    Enum.any?(changeset.errors, fn {_field, {_msg, opts}} ->
      Keyword.get(opts, :constraint) == :unique
    end)
  end

  @doc "Format changeset or other errors into a serializable map."
  def format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  def format_errors(error) when is_binary(error), do: %{base: [error]}
  def format_errors(error) when is_atom(error), do: %{base: [to_string(error)]}
  def format_errors(_), do: %{}
end
