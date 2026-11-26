{
  description = "beacox-gdb-mcp: Multi-session MCP server for GDB and gdbserver";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python312;
        gdbMcp = python.pkgs.buildPythonApplication {
          pname = "beacox-gdb-mcp";
          version = "0.6.0";
          pyproject = true;

          src = ./.;

          build-system = with python.pkgs; [
            setuptools
            wheel
          ];

          dependencies = with python.pkgs; [
            mcp
          ];

          nativeBuildInputs = [ pkgs.makeWrapper ];

          postInstall = ''
            wrapProgram $out/bin/gdb-mcp \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.gdb pkgs.binutils ]}
            wrapProgram $out/bin/gdb-mcp-backend \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.gdb pkgs.binutils ]}
          '';

          doCheck = false;

          meta = with pkgs.lib; {
            description = "Multi-session Model Context Protocol server for GDB and gdbserver";
            homepage = "https://github.com/BeaCox/gdb-mcp";
            license = licenses.mit;
            platforms = platforms.linux;
            mainProgram = "gdb-mcp";
          };
        };
      in
      {
        packages.default = gdbMcp;

        apps.default = flake-utils.lib.mkApp {
          drv = gdbMcp;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            python
            pkgs.uv
            pkgs.gdb
            pkgs.gcc
            pkgs.binutils
          ];
        };
      });
}
