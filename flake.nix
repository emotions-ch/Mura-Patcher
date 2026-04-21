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
            # Include Python files, patches directory, icon, and build config
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

        # Build package - creates Windows executable using PyInstaller cross-compilation
        mura-patcher-build = pkgs.stdenv.mkDerivation {
          pname = "mura-patcher-build";
          version = "1.0.0";

          inherit src;

          nativeBuildInputs = with pkgs; [
            python3
            python3Packages.pyinstaller
            git
          ];

          buildPhase = ''
            export HOME=$TMPDIR

            # Use PyInstaller with Windows target
            # PyInstaller can cross-compile to Windows from Linux
            ${pkgs.python3Packages.pyinstaller}/bin/pyinstaller \
              --onefile \
              --console \
              --target-arch x86_64 \
              --name "Mura Patcher" \
              --icon "mura patcher.ico" \
              --add-data "patches${if pkgs.stdenv.isLinux then ":" else ";"}patches" \
              --add-data "mura patcher.ico${if pkgs.stdenv.isLinux then ":" else ";"}./" \
              --noconfirm \
              --clean \
              patcher.py
          '';

          installPhase = ''
            mkdir -p $out/bin

            # Copy the generated executable
            if [ -f "dist/Mura Patcher.exe" ]; then
              cp "dist/Mura Patcher.exe" $out/bin/mura-patcher.exe
            elif [ -f "dist/Mura Patcher" ]; then
              cp "dist/Mura Patcher" $out/bin/mura-patcher.exe
            elif [ -f "dist/patcher.exe" ]; then
              cp "dist/patcher.exe" $out/bin/mura-patcher.exe
            elif [ -f "dist/patcher" ]; then
              cp "dist/patcher" $out/bin/mura-patcher.exe
            else
              echo "Warning: Executable not found in expected location"
              ls -la dist/ || echo "dist directory not found"
              # Copy any executable file found in dist
              find dist/ -type f \( -name "*.exe" -o -executable \) -exec cp {} $out/bin/mura-patcher.exe \; -quit || true
            fi

            # Also provide the source and patches for reference
            mkdir -p $out/share/mura-patcher-src
            cp patcher.py $out/share/mura-patcher-src/
            cp -r patches $out/share/mura-patcher-src/
            cp "mura patcher.ico" $out/share/mura-patcher-src/
            if [ -f build.json ]; then
              cp build.json $out/share/mura-patcher-src/
            fi
          '';

          meta = with pkgs.lib; {
            description = "Build tools and Windows executable for Mura CMS patcher";
            license = licenses.mit;
            platforms = platforms.unix;
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

          # Build package - for creating Windows executable
          exe = mura-patcher-build;
        };

        # Development shell with all tools needed for development
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            python3
            python3Packages.pyinstaller
            git
          ];

          shellHook = ''
            echo "Mura Patcher Development Environment"
            echo "Available commands:"
            echo "  python3 patcher.py - Run the patcher directly"
            echo "  nix build .#run - Build the runtime package"
            echo "  nix build .#exe - Build the Windows executable"
            echo "  nix run . - Run the patcher application"
          '';
        };

        # Apps for easy running
        apps = {
          default = {
            type = "app";
            program = "${mura-patcher-run}/bin/mura-patcher";
          };

          run = {
            type = "app";
            program = "${mura-patcher-run}/bin/mura-patcher";
          };
        };
      }
    );
}
