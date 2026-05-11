{
  description = "pwdman — a GPG-encrypted password and TOTP manager";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      # All platforms the script can realistically run on.
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system
        nixpkgs.legacyPackages.${system});

    in {

      # -----------------------------------------------------------------------
      # Package
      # -----------------------------------------------------------------------
      packages = forAllSystems (system: pkgs: {

        default = pkgs.stdenvNoCC.mkDerivation {
          pname   = "pwdman";
          version = "1.2";

          src = ./.;

          # Runtime dependencies that must be on PATH when the script runs.
          # Notes:
          #   - coreutils  provides base64, od, mktemp, install, …
          #   - util-linux provides flock  (Linux only; gracefully skipped on macOS)
          #   - gnused     provides sed
          #   - gawk       provides awk  (used in --import-plain old-format migration)
          #   - python3    provides the urllib.parse URL-decoder in pwdman_urldecode
          #   - xxd        is part of vim on nixpkgs; we use the standalone package
          #   - xclip / wl-clipboard are optional — only one needs to be present;
          #     on macOS pbcopy is already in the system, so neither is required.
          nativeBuildInputs = [ pkgs.makeWrapper ];

          runtimeDeps = with pkgs;
            [
              bash
              coreutils   # base64 od mktemp install cat head tail tr
              gnupg
              openssl
              bc
              gnused
              gawk
              python3
              xxd
            ]
            # flock lives in util-linux, which doesn't exist on Darwin
            ++ pkgs.lib.optionals pkgs.stdenvNoCC.isLinux  [ pkgs.util-linux ]
            # On Linux, include both X11 and Wayland clipboard tools so the
            # script can pick whichever is available at runtime.
            ++ pkgs.lib.optionals pkgs.stdenvNoCC.isLinux  [ pkgs.xclip pkgs.wl-clipboard ];

          dontBuild = true;

          installPhase = ''
            runHook preInstall

            install -Dm755 pwdman.sh $out/bin/pwdman

            # Wrap the script so its entire runtime closure is on PATH,
            # regardless of what the user has installed globally.
            wrapProgram $out/bin/pwdman \
              --prefix PATH : ${pkgs.lib.makeBinPath self.packages.${system}.default.runtimeDeps}

            runHook postInstall
          '';

          meta = {
            description  = "A GPG-encrypted password and TOTP manager written in Bash";
            license      = pkgs.lib.licenses.mit;
            mainProgram  = "pwdman";
            platforms    = pkgs.lib.platforms.unix;
          };
        };

      });

      # -----------------------------------------------------------------------
      # App  (lets you run  `nix run .#pwdman -- --help`  or  `nix run .`)
      # -----------------------------------------------------------------------
      apps = forAllSystems (system: _pkgs: {
        default = {
          type    = "app";
          program = "${self.packages.${system}.default}/bin/pwdman";
        };
      });

      # -----------------------------------------------------------------------
      # Dev shell  (`nix develop`)
      # Provides every runtime dep plus shellcheck and bashdb for hacking.
      # -----------------------------------------------------------------------
      devShells = forAllSystems (system: pkgs: {
        default = pkgs.mkShell {
          name = "pwdman-dev";

          packages = self.packages.${system}.default.runtimeDeps ++ (with pkgs; [
            shellcheck   # static analysis
            bashdb       # bash debugger
          ]);

          shellHook = ''
            echo "pwdman dev shell — runtime deps on PATH"
            echo "  shellcheck pwdman.sh"
            echo "  nix run . -- --help"
          '';
        };
      });

    };
}
