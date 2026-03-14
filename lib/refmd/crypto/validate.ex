defmodule RefMD.Crypto.Validate do
  @moduledoc """
  Shared validation helpers for cryptographic binary fields.

  Provides changeset validators for XChaCha20-Poly1305 encrypted envelopes
  (nonce length, ciphertext length) used across all encryption schemas.
  """

  import Ecto.Changeset

  @xchacha20_nonce_bytes 24
  @poly1305_tag_bytes 16

  @spec xchacha20_nonce_bytes() :: non_neg_integer()
  def xchacha20_nonce_bytes, do: @xchacha20_nonce_bytes

  @spec wrapped_key_ciphertext_bytes(non_neg_integer()) :: non_neg_integer()
  def wrapped_key_ciphertext_bytes(key_bytes), do: key_bytes + @poly1305_tag_bytes

  @spec validate_nonce(Ecto.Changeset.t(), atom()) :: Ecto.Changeset.t()
  def validate_nonce(changeset, field \\ :nonce) do
    validate_binary_size(changeset, field, @xchacha20_nonce_bytes)
  end

  @spec validate_wrapped_key(Ecto.Changeset.t(), atom(), non_neg_integer()) :: Ecto.Changeset.t()
  def validate_wrapped_key(changeset, field, key_bytes) do
    validate_binary_size(changeset, field, key_bytes + @poly1305_tag_bytes)
  end

  @spec validate_binary_size(Ecto.Changeset.t(), atom(), non_neg_integer()) :: Ecto.Changeset.t()
  def validate_binary_size(changeset, field, expected) do
    validate_change(changeset, field, fn _, value ->
      if byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end
end
