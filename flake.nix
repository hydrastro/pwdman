{
  description = "pwdman — a GPG-encrypted password and one-time-code (TOTP/HOTP) manager";

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
          version = "2.0";

          src = ./.;

          # Runtime dependencies that must be on PATH when the script runs.
          #   - coreutils  base64 od mktemp sha1sum/sha256sum/sha512sum (the
          #                one-time codes are computed with these, in bash)
          #   - util-linux flock (Linux only; skipped gracefully on macOS)
          #   - fzf        optional: pick entries when no name is given
          #   - zbar       optional: zbarimg reads 2FA QR code images
          #   - qrencode   optional: --otp-export shows a QR code
          #   - xclip / wl-clipboard: only one is needed at runtime;
          #     macOS has pbcopy built in.
          nativeBuildInputs = [ pkgs.makeWrapper ];

          runtimeDeps = with pkgs;
            [
              bash
              coreutils
              gnupg
              fzf
              zbar
              qrencode
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
            description  = "A GPG-encrypted password and one-time-code manager written in Bash";
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
