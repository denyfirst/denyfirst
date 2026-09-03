# The image contains the binary you verified, and nothing else.
#
# It has no base system. A container built on alpine or debian carries several
# hundred packages this project does not audit and cannot reproduce, which
# would put a supply chain underneath a program that deliberately has none:
# go.mod has no require block, and this image has no package manager, no
# shell, and no libc. There is nothing in it to update, and nothing in it to
# take.
#
# It does not build anything either. A builder stage would produce bytes
# nobody has checked, and the whole argument of this project is that the
# release is signed and reproducible. So the binary comes from the release,
# already verified on your own machine — see docs/verify.md — and the image is
# a wrapper around bytes you have already decided to trust.
#
#   curl -fsSLO https://github.com/denyfirst/denyfirst/releases/download/vX.Y.Z/denyfirstd_vX.Y.Z_linux_amd64
#   # ... verify it, then:
#   mv denyfirstd_vX.Y.Z_linux_amd64 denyfirstd
#   docker build -t denyfirst .
#
# The binary is built with CGO_ENABLED=0, so it needs no dynamic loader and no
# libc, which is what makes an empty image possible at all.

FROM scratch

# 65534:65534 is nobody:nogroup on every distribution this is likely to run
# on. Named by number because there is no /etc/passwd in here to resolve a
# name against, and running as root in a container that cannot be entered is
# still a privilege nothing here needs.
USER 65534:65534

COPY --chmod=0555 denyfirstd /denyfirstd

# Above 1024, so no capability is needed to bind it. Port 443 is reached by
# publishing this one, which keeps the binding privilege in the container
# runtime rather than in the program.
EXPOSE 8443

ENTRYPOINT ["/denyfirstd"]
CMD ["-listen", "0.0.0.0:8443"]
