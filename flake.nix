{
  description = "tcpflow: TCP/IP packet demultiplexer";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
    in
    {
      packages = forAllSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.tcpflow;

        tcpflow = pkgs.rustPlatform.buildRustPackage {
          pname = "tcpflow";
          inherit (cargoToml.package) version;

          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./src
              ./tests
              ./doc/completions
              ./doc/tcpflow.1
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.installShellFiles
          ];
          buildInputs = [ pkgs.libpcap ];

          postInstall = ''
            installManPage doc/tcpflow.1
            installShellCompletion --bash --name tcpflow doc/completions/tcpflow.bash
            installShellCompletion --zsh doc/completions/_tcpflow
            installShellCompletion --fish doc/completions/tcpflow.fish
          '';

          meta = {
            description = "TCP/IP packet demultiplexer";
            homepage = "https://github.com/simsong/tcpflow";
            license = pkgs.lib.licenses.gpl3Only;
            mainProgram = "tcpflow";
            platforms = pkgs.lib.platforms.unix;
          };
        };
      });

      # nix flake check: the golden tests against the built binary (SPEC.md 15)
      checks = forAllSystems (
        pkgs:
        let
          tcpflow = self.packages.${pkgs.stdenv.hostPlatform.system}.tcpflow;
        in
        {
          inherit tcpflow;
          conformance =
            pkgs.runCommand "tcpflow-conformance"
              {
                nativeBuildInputs = [ pkgs.python3 ];
              }
              ''
                cp -r ${tcpflow.src} src && chmod -R u+w src && cd src
                python3 -I tests/scripts/conformance.py check ${tcpflow}/bin/tcpflow
                touch $out
              '';
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            pkg-config
            libpcap
            python3
          ];
        };

        # nix develop .#fuzz, then: cargo fuzz run -s none decode (fuzz/README.md).
        # cargo-fuzz needs -Z flags; RUSTC_BOOTSTRAP lets the stable rustc take
        # them. nixpkgs' rustc has no ASan runtime, hence -s none.
        fuzz = pkgs.mkShell {
          inputsFrom = [ self.devShells.${pkgs.stdenv.hostPlatform.system}.default ];
          packages = [ pkgs.cargo-fuzz ];
          RUSTC_BOOTSTRAP = 1;
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
