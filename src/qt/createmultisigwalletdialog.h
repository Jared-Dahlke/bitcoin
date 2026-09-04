// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CREATEMULTISIGWALLETDIALOG_H
#define BITCOIN_QT_CREATEMULTISIGWALLETDIALOG_H

#include <QDialog>
#include <QStringList>

#include <vector>

class QCheckBox;
class QDialogButtonBox;
class QFormLayout;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class WalletModel;

/** Dialog for setting up a multisig wallet.
 *
 * Collects a signature threshold and the extended public key of every
 * cosigner, and assembles a wsh(sortedmulti(...)) output descriptor (keys
 * sorted per BIP 67, receiving and change chains via a multipath element)
 * for a watch-only wallet. Signing is done externally, e.g. by passing
 * PSBTs around the cosigners.
 */
class CreateMultisigWalletDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateMultisigWalletDialog(QWidget* parent);
    ~CreateMultisigWalletDialog();

    QString walletName() const;
    //! Assembled output descriptors (receiving chain first, then change),
    //! including checksums. Empty until the dialog input validates.
    QStringList descriptors() const { return m_descriptors; }
    //! First receiving address derived from the descriptor. Empty until the
    //! dialog input validates.
    QString firstAddress() const { return m_first_address; }
    //! Whether the user indicated the multisig already has transaction
    //! history, so the block chain should be rescanned after import.
    bool rescanNeeded() const;

    //! Offer the given wallets for filling in a cosigner key.
    void setWallets(const std::vector<WalletModel*>& wallets);
    //! Fill in the key of the given cosigner, e.g. after a
    //! walletKeyRequested signal was handled.
    void setCosignerKey(int index, const QString& key);
    //! Currently entered key of the given cosigner (trimmed), or an empty
    //! string if the index is out of range.
    QString cosignerKey(int index) const;

Q_SIGNALS:
    //! Emitted when the user asks for a cosigner key to be filled in from
    //! one of the loaded wallets.
    void walletKeyRequested(int index, WalletModel* wallet_model);

private Q_SLOTS:
    void updateCosignerRows();
    void validate();

private:
    void updateWalletMenus();
    //! Fill in the key of the given cosigner from a user-chosen text file.
    void loadCosignerKeyFromFile(int index);

    QLineEdit* m_wallet_name;
    QCheckBox* m_rescan_checkbox;
    QSpinBox* m_required_spin;
    QSpinBox* m_total_spin;
    QFormLayout* m_cosigner_form;
    std::vector<QLineEdit*> m_cosigner_edits;
    std::vector<QWidget*> m_cosigner_rows;
    std::vector<QPushButton*> m_cosigner_wallet_buttons;
    std::vector<WalletModel*> m_wallet_models;
    QPlainTextEdit* m_descriptor_preview;
    QLabel* m_address_label;
    QLabel* m_status_label;
    QPushButton* m_copy_button;
    QDialogButtonBox* m_button_box;

    QStringList m_descriptors;
    QString m_first_address;
};

#endif // BITCOIN_QT_CREATEMULTISIGWALLETDIALOG_H
