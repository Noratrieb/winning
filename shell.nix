{ pkgs ? import <nixpkgs> { } }: pkgs.mkShell {
  packages = with pkgs; [
    llvmPackages_20.clang-unwrapped
  ];
}
