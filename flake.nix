{
  description = "Mura CMS Security Patcher - A tool for patching security vulnerabilities in Mura CMS installations";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }@inputs:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Common source files needed for both outputs
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter =
            name: type:
            let
              baseName = baseNameOf name;
            in
            # Include Python files, patches directory, icon, build config, and Windows build scripts
            (pkgs.lib.hasSuffix ".py" baseName)
            || (baseName == "patches")
            || (baseName == "mura patcher.ico")
            || (baseName == "build.json")
            || (type == "directory" && baseName != ".git" && baseName != "result");
        };

        # Runtime package - runs the Python application directly
        mura-patcher-run = pkgs.stdenv.mkDerivation {
          pname = "mura-patcher";
          version = "1.0.0";

          inherit src;

          nativeBuildInputs = with pkgs; [ makeWrapper ];
          buildInputs = with pkgs; [
            python3
            git
          ];

          installPhase = ''
            mkdir -p $out/bin $out/share/mura-patcher

            # Copy application files
            cp patcher.py $out/share/mura-patcher/
            cp -r patches $out/share/mura-patcher/
            cp "mura patcher.ico" $out/share/mura-patcher/

            # Create wrapper script
            makeWrapper ${pkgs.python3}/bin/python3 $out/bin/mura-patcher \
              --add-flags "$out/share/mura-patcher/patcher.py" \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.git ]} \
              --chdir "$out/share/mura-patcher"
          '';

          meta = with pkgs.lib; {
            description = "Security patcher for Mura CMS installations";
            license = licenses.mit;
            platforms = platforms.unix;
            mainProgram = "mura-patcher";
          };
        };
      in
      {
        formatter = inputs.nixpkgs.legacyPackages.${system}.nixfmt-tree;
        packages = {
          # Default package is the runtime version
          default = mura-patcher-run;

          # Runtime package - for running the application directly
          run = mura-patcher-run;
        };

        # Development shell with all tools needed for development
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            python3
            git
          ];

          shellHook = ''
            echo "Mura Patcher Development Environment"
            echo "Available commands:"
            echo "  python3 patcher.py - Run the patcher directly on Linux"
            echo "  nix build .#run - Build the runtime package (Linux)"
            echo "  nix build .#exe - Get Windows build scripts and setup"
            echo "  nix run . - Run the patcher application"
          '';
        };

        # Apps for easy running
        apps = {
          default = {
            type = "app";
            program = "${mura-patcher-run}/bin/mura-patcher";
          };
        };
      }
    );
}
