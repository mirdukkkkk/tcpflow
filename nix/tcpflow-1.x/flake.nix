# tcpflow 1.x (C++). Copy this flake and its flake.lock into a checkout of
# main or a fix/* branch, then: nix build path:.#tcpflow
{
  description = "tcpflow 1.x: TCP/IP packet demultiplexer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Pinned to the same revision as the src/http-parser git submodule.
    # Flake sources do not include submodules, so it is fetched separately.
    http-parser = {
      url = "github:nodejs/http-parser/87e395602053feb3506cf099b535ba7325ed7ab0";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      http-parser,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.tcpflow;

        tcpflow = pkgs.stdenv.mkDerivation {
          pname = "tcpflow";
          version = "1.6.2";

          src = self;

          postUnpack = ''
            rm -rf "$sourceRoot/src/http-parser"
            cp -r ${http-parser} "$sourceRoot/src/http-parser"
            chmod -R u+w "$sourceRoot/src/http-parser"
          '';

          nativeBuildInputs = with pkgs; [
            autoreconfHook
            pkg-config
          ];

          buildInputs =
            with pkgs;
            [
              boost
              cairo
              libpcap
              openssl
              zlib
            ]
            ++ lib.optionals stdenv.hostPlatform.isLinux [ libcap_ng ];

          enableParallelBuilding = true;

          # The shell tests compare output files using `openssl md5`.
          doCheck = true;
          nativeCheckInputs = [ pkgs.openssl ];

          # The tests call /bin/rm, which does not exist in the Nix sandbox.
          # netviz (cairo) needs a fontconfig config and a writable cache dir.
          preCheck = ''
            substituteInPlace tests/*.sh tests/Makefile --replace-quiet /bin/rm rm
            export HOME="$TMPDIR"
            export FONTCONFIG_FILE=${pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; }}
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

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.tcpflow ];
          packages = with pkgs; [
            autoconf
            automake
            libtool
            cmake
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
