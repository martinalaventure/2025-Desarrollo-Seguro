// src/services/invoiceService.ts
import db from '../db';
import { Invoice } from '../types/invoice';
import axios from 'axios';
import { promises as fs } from 'fs';
import * as path from 'path';

interface InvoiceRow {
  id: string;
  userId: string;
  amount: number;
  dueDate: Date;
  status: string;
}

class InvoiceService {
  static async list(
    userId: string,
    status?: string,
    operator?: string
  ): Promise<Invoice[]> {
    let q = db<InvoiceRow>("invoices").where({ userId: userId });

    if (status && operator) {
      const validOperators = ["=", "!=", "<", ">", "<=", ">="];
      if (!validOperators.includes(operator)) {
        throw new Error("Invalid operator");
      }

      if (!/^[a-zA-Z0-9_-]+$/.test(status)) {
        throw new Error("Invalid status format");
      }

      q = q.andWhere("status", operator, status);
    }
    const rows = await q.select();
    const invoices = rows.map(
      (row) =>
        ({
          id: row.id,
          userId: row.userId,
          amount: row.amount,
          dueDate: row.dueDate,
          status: row.status,
        } as Invoice)
    );
    return invoices;
  }

  static async setPaymentCard(
    userId: string,
    invoiceId: string,
    paymentBrand: string,
    ccNumber: string,
    ccv: string,
    expirationDate: string
  ) {
    // use axios to call http://paymentBrand/payments as a POST request
    // with the body containing ccNumber, ccv, expirationDate
    // and handle the response accordingly
    if (!this.isAllowedPaymentDomain(paymentBrand)) {
      throw new Error('Dominio de pago no permitido');
    }

    const paymentUrl = `https://${paymentBrand}/payments`;

    const paymentResponse = await axios.post(paymentUrl, {
      ccNumber,
      ccv,
      expirationDate
    });

    if (paymentResponse.status !== 200) {
      throw new Error('Payment failed');
    }

    // Update the invoice status in the database
    await db('invoices')
      .where({ id: invoiceId, userId })
      .update({ status: 'paid' });  
    };
  
    static async  getInvoice( invoiceId:string): Promise<Invoice> {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    return invoice as Invoice;
  }

  private static readonly INVOICES_BASE_DIR = path.resolve(__dirname, '../../invoices');

  static async getReceipt(
    invoiceId: string,
    pdfName: string
  ) {
    const safePath = path.join(this.INVOICES_BASE_DIR, pdfName);

    if (!this.isValidFileName(pdfName)) {
      throw new Error('Nombre de archivo inválido');
  }

    if (!this.isPathWithinDirectory(safePath, this.INVOICES_BASE_DIR)) {
      throw new Error('Intento de acceso fuera del directorio permitido');
    }
    // check if the invoice exists
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    try {
      const content = await fs.readFile(safePath);
      return content;
    } catch (error) {
      // send the error to the standard output
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');

    } 

  };

  // Validar que el nombre de archivo sea seguro
  private static isValidFileName(fileName: string): boolean {
    // No permitir caracteres especiales o path traversal
    const invalidPatterns = [
      /\.\./, // No permitir ".."
      /\/\\/, // No permitir slashes
      /^\./, // No permitir que empiece con punto
      /[<>:"|?*]/, // No permitir caracteres especiales de Windows
    ];

    return !invalidPatterns.some(pattern => pattern.test(fileName)) &&
      /^[a-zA-Z0-9_\-\.]+\.pdf$/.test(fileName); // Solo nombres seguros con extensión .pdf
  }


  private static isPathWithinDirectory(filePath: string, directory: string): boolean {
    const resolvedFilePath = path.resolve(filePath);
    const resolvedDirectory = path.resolve(directory);

    return resolvedFilePath.startsWith(resolvedDirectory);
  }

  private static isAllowedPaymentDomain(domain: string): boolean {
  try {
    const domainObj = new URL(`https://${domain}`);
    const hostname = domainObj.hostname.toLowerCase();

    return this.ALLOWED_PAYMENT_DOMAINS.has(hostname) ||
           this.ALLOWED_PAYMENT_DOMAINS.has(hostname.replace(/^www\./, ''));
  } catch (e) {
    return false;
  }
}


  private static readonly ALLOWED_PAYMENT_DOMAINS = new Set([
  'visa.com',
  'mastercard.com',
  'amex.com',
  'paypal.com'
]);


};

export default InvoiceService;
