class Aegispq < Formula
  desc "Post-quantum hybrid encryption CLI — X25519+ML-KEM-768, Ed25519+ML-DSA-65"
  homepage "https://github.com/klanssrklbp/AegisPQ"
  license any_of: ["MIT", "Apache-2.0"]

  # Updated by release automation — do not edit manually.
  url "https://github.com/klanssrklbp/AegisPQ/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER"
  version "0.1.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install",
           "--locked",
           "--root", prefix,
           "--path", "crates/aegispq-cli"
  end

  test do
    assert_match "aegispq", shell_output("#{bin}/aegispq version --json")
  end
end
