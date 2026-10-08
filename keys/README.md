Generate a development image-signing key here (never use it for products):

    imgtool keygen -k fw_signing_DEV_ONLY.pem -t ecdsa-p256

Production images are signed with the DTII release key held in an HSM.
`*.pem` files are git-ignored.
